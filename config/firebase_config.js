// Firebase Firestore Client Configuration for Sentinel NIDS
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
import { getFirestore, collection, onSnapshot, query, orderBy, limit, addDoc } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-firestore.js";

const firebaseConfig = {
  apiKey: "AIzaSySENTINEL_SOC_API_KEY_DEMO",
  authDomain: "sentinel-nids-soc.firebaseapp.com",
  projectId: "sentinel-nids-soc",
  storageBucket: "sentinel-nids-soc.appspot.com",
  messagingSenderId: "109823485721",
  appId: "1:109823485721:web:9f8e7d6c5b4a3"
};

// Initialize Firebase
export const app = initializeApp(firebaseConfig);
export const db = getFirestore(app);

// Real-time listener for incoming intrusion alerts
export function subscribeToSentinelIncidents(callback) {
  const q = query(
    collection(db, "sentinel_incidents"),
    orderBy("timestamp", "desc"),
    limit(25)
  );

  return onSnapshot(q, (snapshot) => {
    snapshot.docChanges().forEach((change) => {
      if (change.type === "added") {
        callback(change.doc.data());
      }
    });
  });
}
