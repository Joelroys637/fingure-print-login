const admin = require("firebase-admin");
const dotenv = require("dotenv");

dotenv.config();

// Placeholder for Service Account Key
// In a real scenario, this should be an environment variable or a file excluded from git
// For this demo, we will check if a file exists or use specific env vars
// YOU (USER) NEED TO REPLACE THIS WITH YOUR ACTUAL SERVICE ACCOUNT KEY
let serviceAccount;

try {
    serviceAccount = require("./serviceAccountKey.json");
} catch (e) {
    console.warn("serviceAccountKey.json not found. Database operations will fail until provided.");
    serviceAccount = {}; // Empty object to allow server to start, but DB calls will fail
}

if (Object.keys(serviceAccount).length > 0) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
    console.log("Firebase Admin Initialized");
} else {
    console.warn("Skipping Firebase initialization due to missing key.");
}

let db;
try {
    if (admin.apps.length > 0) {
        db = admin.firestore();
    } else {
        // Mock db to allow server start, operations will fail
        console.warn("DB not initialized - operations will throw errors.");
        db = {
            collection: () => ({
                doc: () => ({
                    set: async () => { throw new Error("DB not connected"); },
                    get: async () => { throw new Error("DB not connected"); }
                }),
                get: async () => { return { forEach: () => { } }; } // Mock empty get
            })
        };
    }
} catch (e) {
    console.error("Error initializing DB handle:", e);
}

module.exports = { admin, db };
