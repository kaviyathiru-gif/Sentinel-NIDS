"""
Sentinel MLDL Model Training Script
Trains the SentinelNeuralIDS dual-head network on network telemetry data.
Outputs:
  - Checkpoint: sentinel_ids_best.pth
  - Preprocessor statistics: preprocessor_params.json
"""

import json
import os
import numpy as np

# Note: In environments with PyTorch installed, run this directly.
try:
    import torch
    import torch.nn as nn
    from torch.utils.data import Dataset, DataLoader
    from model import SentinelNeuralIDS, ATTACK_CLASSES, FEATURE_NAMES
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    from model.dataset import FEATURE_NAMES

from dataset import generate_synthetic_traffic, NetworkTrafficPreprocessor

if TORCH_AVAILABLE:
    class FlowDataset(Dataset):
        def __init__(self, X, y_bin, y_multi):
            self.X = torch.tensor(X, dtype=torch.float32)
            self.y_bin = torch.tensor(y_bin, dtype=torch.float32)
            self.y_multi = torch.tensor(y_multi, dtype=torch.long)

        def __len__(self):
            return len(self.X)

        def __getitem__(self, idx):
            return self.X[idx], self.y_bin[idx], self.y_multi[idx]

def train_sentinel_model(epochs=20, batch_size=64, lr=1e-3, output_dir="checkpoints"):
    os.makedirs(output_dir, exist_ok=True)

    print("==> Generating benchmark network intrusion dataset...")
    X, y_bin, y_multi = generate_synthetic_traffic(num_samples=10000, random_seed=42)

    # Train / Validation / Test split (70% / 15% / 15%)
    n = len(X)
    n_train = int(0.7 * n)
    n_val = int(0.15 * n)

    X_train, y_bin_train, y_multi_train = X[:n_train], y_bin[:n_train], y_multi[:n_train]
    X_val, y_bin_val, y_multi_val = X[n_train:n_train+n_val], y_bin[n_train:n_train+n_val], y_multi[n_train:n_train+n_val]
    X_test, y_bin_test, y_multi_test = X[n_train+n_val:], y_bin[n_train+n_val:], y_multi[n_train+n_val:]

    # Preprocessing
    preprocessor = NetworkTrafficPreprocessor()
    X_train_norm = preprocessor.fit_transform(X_train)
    X_val_norm = preprocessor.transform(X_val)
    X_test_norm = preprocessor.transform(X_test)

    # Save Preprocessor normalization parameters
    preprocessor_data = {
        "features": FEATURE_NAMES,
        "mean": preprocessor.mean.tolist(),
        "std": preprocessor.std.tolist()
    }
    with open(os.path.join(output_dir, "preprocessor_params.json"), "w") as f:
        json.dump(preprocessor_data, f, indent=2)
    print(" Saved feature normalization parameters.")

    if not TORCH_AVAILABLE:
        print(" PyTorch not installed in this execution environment. Preprocessor metadata exported successfully.")
        return

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f" Training on device: {device}")

    train_ds = FlowDataset(X_train_norm, y_bin_train, y_multi_train)
    val_ds = FlowDataset(X_val_norm, y_bin_val, y_multi_val)

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False)

    model = SentinelNeuralIDS(input_dim=len(FEATURE_NAMES), num_classes=len(ATTACK_CLASSES)).to(device)

    # Loss definitions: Dual Multi-Task Objective
    criterion_bin = nn.BCEWithLogitsLoss()
    criterion_multi = nn.CrossEntropyLoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    best_val_f1 = 0.0
    checkpoint_path = os.path.join(output_dir, "sentinel_ids_best.pth")

    for epoch in range(1, epochs + 1):
        model.train()
        running_loss = 0.0
        correct_bin = 0
        correct_multi = 0
        total = 0

        for x_b, y_b, y_m in train_loader:
            x_b, y_b, y_m = x_b.to(device), y_b.to(device), y_m.to(device)
            optimizer.zero_grad()

            outputs = model(x_b)
            loss_bin = criterion_bin(outputs["binary_logits"].squeeze(-1), y_b)
            loss_multi = criterion_multi(outputs["multiclass_logits"], y_m)

            # Combined multitask loss
            loss = 0.4 * loss_bin + 0.6 * loss_multi
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

            running_loss += loss.item() * len(x_b)
            total += len(x_b)

            bin_preds = (torch.sigmoid(outputs["binary_logits"].squeeze(-1)) >= 0.5).long()
            correct_bin += (bin_preds == y_b.long()).sum().item()

            multi_preds = torch.argmax(outputs["multiclass_logits"], dim=-1)
            correct_multi += (multi_preds == y_m).sum().item()

        scheduler.step()

        # Validation loop
        model.eval()
        val_loss = 0.0
        val_correct_bin = 0
        val_correct_multi = 0
        val_total = 0

        with torch.no_grad():
            for x_b, y_b, y_m in val_loader:
                x_b, y_b, y_m = x_b.to(device), y_b.to(device), y_m.to(device)
                outputs = model(x_b)
                loss_b = criterion_bin(outputs["binary_logits"].squeeze(-1), y_b)
                loss_m = criterion_multi(outputs["multiclass_logits"], y_m)
                v_loss = 0.4 * loss_b + 0.6 * loss_m

                val_loss += v_loss.item() * len(x_b)
                val_total += len(x_b)

                bin_p = (torch.sigmoid(outputs["binary_logits"].squeeze(-1)) >= 0.5).long()
                val_correct_bin += (bin_p == y_b.long()).sum().item()

                multi_p = torch.argmax(outputs["multiclass_logits"], dim=-1)
                val_correct_multi += (multi_p == y_m).sum().item()

        val_bin_acc = val_correct_bin / val_total
        val_multi_acc = val_correct_multi / val_total

        print(f"Epoch [{epoch:02d}/{epochs}] "
              f"Train Loss: {running_loss/total:.4f} | "
              f"Val Loss: {val_loss/val_total:.4f} | "
              f"Hacker Det Acc: {val_bin_acc*100:.2f}% | "
              f"Attack Class Acc: {val_multi_acc*100:.2f}%")

        if val_multi_acc > best_val_f1:
            best_val_f1 = val_multi_acc
            torch.save({
                "epoch": epoch,
                "model_state_dict": model.state_dict(),
                "optimizer_state_dict": optimizer.state_dict(),
                "val_accuracy": val_multi_acc,
                "input_dim": len(FEATURE_NAMES),
                "num_classes": len(ATTACK_CLASSES),
                "attack_classes": ATTACK_CLASSES
            }, checkpoint_path)

    print(f" Best model saved to: {checkpoint_path}")

if __name__ == "__main__":
    train_sentinel_model(epochs=15, batch_size=64)
