// MongoDB initialization script
db = db.getSiblingDB('edr_scanner');

// Create collections with indexes
db.createCollection('scan_logs');
db.scan_logs.createIndex({ "scan_time": 1 });
db.scan_logs.createIndex({ "scan_id": 1 });

print('EDR Scanner database initialized');