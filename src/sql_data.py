import sqlite3
import random

# 🌟 DETERMINISTIC SEED: Guarantees the same 50 records per table every time.
random.seed(42)

DB_PATH = "/opt/t-airs/src/customers.db"

# --- HELPER FUNCTIONS FOR VALID DLP PAYLOADS ---

def get_luhn_check_digit(number_string):
    """Calculates the mathematically valid Luhn check digit for a CC base."""
    total = 0
    for i, digit in enumerate(reversed(number_string)):
        n = int(digit)
        if i % 2 == 0:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return str((10 - (total % 10)) % 10)

def generate_valid_cc():
    """Generates a mathematically valid 16-digit credit card number."""
    prefixes = ['4111', '5105', '6011'] # Visa, Mastercard, Discover test BINs
    prefix = random.choice(prefixes)
    core = prefix + ''.join(str(random.randint(0, 9)) for _ in range(11))
    return core + get_luhn_check_digit(core)

def generate_ssn():
    return f"{random.randint(101,899):03d}-{random.randint(11,99):02d}-{random.randint(1001,9999):04d}"

# --- MAIN SEEDER ---

def seed_database():
    print(f"🌱 Building deterministic, structurally valid records for ALL personas in {DB_PATH}...")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Common name pools
    firsts = ['james', 'mary', 'robert', 'patricia', 'john', 'jennifer', 'michael', 'linda', 'william', 'elizabeth', 'david', 'barbara', 'richard', 'susan', 'joseph']
    lasts = ['smith', 'johnson', 'williams', 'brown', 'jones', 'garcia', 'milland', 'davis', 'rodriguez', 'martinez', 'hernandez', 'lopez', 'gonzalez', 'wilson', 'anderson']

    # ==========================================
    # 1. BANKING PERSONA ('bank_accounts')
    # ==========================================
    print("   -> Seeding 'bank_accounts' (Banking)...")
    cursor.execute("DROP TABLE IF EXISTS bank_accounts")
    cursor.execute('''CREATE TABLE bank_accounts (id INTEGER PRIMARY KEY, name TEXT, balance REAL, notes TEXT, ssn TEXT, cc_number TEXT, tax_id TEXT, national_id TEXT, personal_identity_code TEXT)''')
    
    banking_data = [(10001, 'a_miller', 15000.50, 'VIP member. Handle with care.', '843-92-1049', '4111-1111-1111-1111', '12-3456789', 'NID-94827591', '120485-123U')]
    
    for i in range(10002, 10051):
        name = f"{random.choice(firsts)}_{random.choice(lasts)}"
        raw_cc = generate_valid_cc()
        cc_formatted = f"{raw_cc[:4]}-{raw_cc[4:8]}-{raw_cc[8:12]}-{raw_cc[12:]}"
        banking_data.append((
            i, name, round(random.uniform(-500, 100000), 2), 
            random.choice(['Active', 'Frozen', 'Premier status', 'Overdrawn']), 
            generate_ssn(), cc_formatted, 
            f"{random.randint(10,99):02d}-{random.randint(1000000,9999999):07d}", 
            f"NID-{random.randint(10000000,99999999)}", 
            f"{random.randint(100000,999999)}-{random.choice(['A','B','C','D'])}{random.randint(100,999)}"
        ))
    cursor.executemany('INSERT INTO bank_accounts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', banking_data)

    # ==========================================
    # 2. AIRLINE PERSONA ('passenger_manifest')
    # ==========================================
    print("   -> Seeding 'passenger_manifest' (Airline)...")
    cursor.execute("DROP TABLE IF EXISTS passenger_manifest")
    
    # 🌟 Added cabin_class as the final column
    cursor.execute('''CREATE TABLE passenger_manifest (booking_reference TEXT, flight_id TEXT, passenger_name TEXT, passport_number TEXT, dob TEXT, ticket_number TEXT, tsa_precheck_id TEXT, payment_card TEXT, cabin_class TEXT)''')
    
    # 🌟 Added 'First' class for our VIP a_miller
    airline_data = [
        ('XYZ789', 'FL-921', 'a_miller', 'C44920018', '05/14/1985', 'TKT-1004593021', 'KTN843921', '4111111111111111', 'First')
    ]
    
    for _ in range(49): 
        name = f"{random.choice(firsts).capitalize()} {random.choice(lasts).capitalize()}"
        raw_cc = generate_valid_cc()
        booking_ref = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=6))
        
        # Randomly assign a cabin class
        cabin = random.choice(['Economy', 'Premium Economy', 'Business', 'First'])
        
        airline_data.append((
            booking_ref,
            f"FL-{random.randint(100,999)}", 
            name, 
            f"C{random.randint(10000000,99999999)}", # Passport
            f"{random.randint(1,12):02d}/{random.randint(1,28):02d}/{random.randint(1950,2005)}", 
            f"TKT-{random.randint(1000000000,9999999999)}", 
            f"KTN{random.randint(100000,999999)}", 
            raw_cc, # Unformatted CC
            cabin   # 🌟 The new cabin class variable
        ))
        
    # 🌟 Updated to 9 question marks to match the 9 columns
    cursor.executemany('INSERT INTO passenger_manifest VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', airline_data)

    # ==========================================
    # 3. E-COMMERCE PERSONA ('pending_orders')
    # ==========================================
    print("   -> Seeding 'pending_orders' (E-commerce)...")
    cursor.execute("DROP TABLE IF EXISTS pending_orders")
    cursor.execute('''CREATE TABLE pending_orders (order_id INTEGER PRIMARY KEY, customer_name TEXT, contact_email TEXT, phone_number TEXT, credit_card TEXT, billing_zip TEXT)''')
    
    ecommerce_data = [
        (5000, 'a_miller', 'a_miller@example.com', '(555) 123-4567', '4111-1111-1111-1111', '90210')
    ]
    for i in range(5001, 5050):
        fname, lname = random.choice(firsts), random.choice(lasts)
        raw_cc = generate_valid_cc()
        cc_formatted = f"{raw_cc[:4]}-{raw_cc[4:8]}-{raw_cc[8:12]}-{raw_cc[12:]}"
        ecommerce_data.append((
            i, f"{fname.capitalize()} {lname.capitalize()}", 
            f"{fname}.{lname}{random.randint(1,99)}@example.com", 
            f"(555) {random.randint(100,999)}-{random.randint(1000,9999)}", 
            cc_formatted, 
            f"{random.randint(10000,99999)}"
        ))
    cursor.executemany('INSERT INTO pending_orders VALUES (?, ?, ?, ?, ?, ?)', ecommerce_data)


    conn.commit()
    conn.close()
    print("✅ All persona databases successfully seeded!")

if __name__ == "__main__":
    seed_database()
