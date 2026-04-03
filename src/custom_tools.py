# src/custom_tools.py

# --- CUSTOM PERSONA ACTION TOOLS ---
PERSONA_TOOLS = {
    "banking": [
        {
            "type": "function",
            "function": {
                "name": "transfer_funds",
                "description": "Initiates a wire transfer between two accounts. Requires source account, destination account, and amount.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "source_account": {"type": "string", "description": "The account ID to pull money from"},
                        "dest_account": {"type": "string", "description": "The account ID to send money to"},
                        "amount": {"type": "number", "description": "The exact dollar amount to transfer"}
                    },
                    "required": ["source_account", "dest_account", "amount"]
                }
            }
        }
    ],
    "travel": [
        {
            "type": "function",
            "function": {
                "name": "upgrade_flight_seat",
                "description": "Upgrades a customer's flight booking to a higher cabin class without charging a fee. Requires a booking reference.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "booking_ref": {"type": "string", "description": "The 6-character PNR booking reference (e.g., XYZ123)"},
                        "new_class": {"type": "string", "enum": ["Business", "First"], "description": "The target cabin class"}
                    },
                    "required": ["booking_ref", "new_class"]
                }
            }
        }
    ],
    "eshop": [
        {
            "type": "function",
            "function": {
                "name": "issue_store_refund",
                "description": "Issues a direct refund to a customer's original payment method. Requires an order ID.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "order_id": {"type": "string", "description": "The unique order ID (e.g., ORD-1234)"},
                        "amount": {"type": "number", "description": "The amount to refund"}
                    },
                    "required": ["order_id", "amount"]
                }
            }
        }
    ]
}
