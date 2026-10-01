"""
Sentinel MLDL Intrusion Detection Engine
PyTorch Deep Learning Model Architecture: Hybrid 1D-CNN + BiLSTM + Multi-Head Self-Attention
Dual-Head Classifier:
  1. Anomaly Detection Head: Binary classification (Normal User vs. Hacker/Intruder)
  2. Multi-Class Attack Head: Categorization (Normal, Port Scanning, Brute Force, DDoS, Botnet C2)
"""

import torch
import torch.nn as nn
import torch.nn.functional as F

ATTACK_CLASSES = {
    0: "Normal Traffic",
    1: "Port Scanning",
    2: "Brute Force",
    3: "DDoS / SYN Flood",
    4: "Botnet C2"
}

FEATURE_NAMES = [
    "flow_duration_ms",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "packet_length_mean",
    "packet_length_std",
    "syn_flag_count",
    "fin_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "ack_flag_count",
    "urg_flag_count",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "dst_port_entropy",
    "failed_logins",
    "down_up_ratio",
    "avg_packet_size",
    "fwd_header_length",
    "bwd_header_length",
    "active_mean_ms",
    "idle_mean_ms",
    "connection_retry_rate"
]

class AttentionBlock(nn.Module):
    def __init__(self, hidden_dim):
        super(AttentionBlock, self).__init__()
        self.attention_weights = nn.Linear(hidden_dim, 1, bias=False)

    def forward(self, x):
        # x shape: (batch_size, seq_len, hidden_dim)
        scores = self.attention_weights(x)  # (batch_size, seq_len, 1)
        weights = F.softmax(scores, dim=1)  # (batch_size, seq_len, 1)
        context = torch.sum(weights * x, dim=1)  # (batch_size, hidden_dim)
        return context, weights.squeeze(-1)

class SentinelNeuralIDS(nn.Module):
    """
    State-of-the-Art Deep Learning Intrusion Detection System
    Input: Normalized network traffic flow vectors of dimension len(FEATURE_NAMES)
    """
    def __init__(self, input_dim=len(FEATURE_NAMES), num_classes=len(ATTACK_CLASSES)):
        super(SentinelNeuralIDS, self).__init__()
        self.input_dim = input_dim
        self.num_classes = num_classes

        # 1. 1D-Convolutional Feature Extractor (Reshaped as sequence of sub-features)
        self.conv1 = nn.Conv1d(in_channels=1, out_channels=32, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm1d(32)
        self.conv2 = nn.Conv1d(in_channels=32, out_channels=64, kernel_size=3, padding=1)
        self.bn2 = nn.BatchNorm1d(64)
        self.pool = nn.MaxPool1d(kernel_size=2)
        self.dropout_conv = nn.Dropout(0.25)

        # 2. Bidirectional LSTM for Temporal / Feature Sequencing
        conv_output_dim = input_dim // 2
        self.lstm = nn.LSTM(
            input_size=64,
            hidden_size=64,
            num_layers=2,
            batch_first=True,
            bidirectional=True,
            dropout=0.2
        )

        # 3. Attention Layer
        self.attention = AttentionBlock(hidden_dim=128)  # 64 * 2 (bidirectional)

        # 4. Dense Representation Layer
        self.fc_shared = nn.Sequential(
            nn.Linear(128, 128),
            nn.BatchNorm1d(128),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.3)
        )

        # 5. Dual Task Heads:
        # Head A: Binary Intrusion Detection (0: Normal, 1: Hacker)
        self.binary_head = nn.Sequential(
            nn.Linear(128, 32),
            nn.ReLU(),
            nn.Linear(32, 1)  # Output logits for BCEWithLogitsLoss
        )

        # Head B: Multi-Class Attack Specifics (Normal, Port Scan, Brute Force, DDoS, Botnet)
        self.multiclass_head = nn.Sequential(
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, num_classes)  # CrossEntropyLoss
        )

    def forward(self, x):
        # x shape: (batch_size, input_dim)
        batch_size = x.size(0)

        # Expand to (batch_size, 1, input_dim) for 1D convolution
        x_conv = x.unsqueeze(1)
        c1 = F.leaky_relu(self.bn1(self.conv1(x_conv)), 0.2)
        c2 = F.leaky_relu(self.bn2(self.conv2(c1)), 0.2)
        p = self.pool(c2)  # (batch_size, 64, input_dim // 2)
        p = self.dropout_conv(p)

        # Permute to (batch_size, seq_len, channels) for LSTM
        lstm_in = p.permute(0, 2, 1)  # (batch_size, input_dim // 2, 64)
        lstm_out, _ = self.lstm(lstm_in)  # (batch_size, seq_len, 128)

        # Attention pooling
        context, attn_weights = self.attention(lstm_out)  # (batch_size, 128)

        # Shared representation
        features = self.fc_shared(context)

        # Predictions
        is_hacker_logit = self.binary_head(features)  # (batch_size, 1)
        attack_logits = self.multiclass_head(features)  # (batch_size, num_classes)

        return {
            "binary_logits": is_hacker_logit,
            "multiclass_logits": attack_logits,
            "attention_weights": attn_weights,
            "latent_features": features
        }

    def predict(self, x, threshold=0.5):
        """
        Inference helper returning structured detection results.
        """
        self.eval()
        with torch.no_grad():
            outputs = self.forward(x)
            hacker_prob = torch.sigmoid(outputs["binary_logits"]).squeeze(-1)
            is_hacker = (hacker_prob >= threshold).long()

            attack_probs = F.softmax(outputs["multiclass_logits"], dim=-1)
            attack_class_id = torch.argmax(attack_probs, dim=-1)
            attack_confidence = torch.max(attack_probs, dim=-1)[0]

            return {
                "is_hacker": is_hacker.cpu().numpy(),
                "hacker_probability": hacker_prob.cpu().numpy(),
                "attack_class_id": attack_class_id.cpu().numpy(),
                "attack_name": [ATTACK_CLASSES[cid] for cid in attack_class_id.cpu().numpy()],
                "attack_confidence": attack_confidence.cpu().numpy(),
                "class_probabilities": attack_probs.cpu().numpy()
            }
