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
                        "source_account": {"type": "integer", "description": "The numeric account ID to pull money from"},
                        "dest_account": {"type": "integer", "description": "The numeric account ID to send money to"},
                        "amount": {"type": "number", "description": "The exact dollar amount to transfer"}
                    },
                    "required": ["source_account", "dest_account", "amount"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "freeze_account",
                "description": "Immediately freezes a bank account for suspected fraud. Requires the account ID and a reason.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "account_id": {"type": "integer", "description": "The unique numeric account ID"},
                        "reason": {"type": "string", "description": "Reason for the freeze (e.g., 'Suspicious Activity')"}
                    },
                    "required": ["account_id", "reason"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "issue_replacement_card",
                "description": "Cancels the current credit card and issues a new one. Requires the account ID.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "account_id": {"type": "integer", "description": "The numeric account ID"}
                    },
                    "required": ["account_id"]
                }
            }
        }
    ],
    "travel": [
        {
            "type": "function",
            "function": {
                "name": "upgrade_flight_seat",
                "description": "Upgrades a customer's flight booking to a higher cabin class without charging a fee. Requires a ticket number.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ticket_number": {"type": "string", "description": "The official booking ticket number (e.g., TKT-1234567890)"},
                        "new_class": {"type": "string", "enum": ["Business", "First"], "description": "The target cabin class"}
                    },
                    "required": ["ticket_number", "new_class"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "cancel_flight_booking",
                "description": "Cancels a flight completely and revokes the ticket. Requires the ticket number.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ticket_number": {"type": "string", "description": "The official booking ticket number"},
                        "refund_to_card": {"type": "boolean", "description": "True to refund the stored payment card, False to issue flight credit"}
                    },
                    "required": ["ticket_number", "refund_to_card"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "update_passport_details",
                "description": "Updates the passport document number associated with a flight. Requires the ticket number and new passport ID.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ticket_number": {"type": "string", "description": "The official booking ticket number"},
                        "new_passport_id": {"type": "string", "description": "The new passport document number"}
                    },
                    "required": ["ticket_number", "new_passport_id"]
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
                        "order_id": {"type": "integer", "description": "The unique integer order ID (e.g., 5001)"},
                        "amount": {"type": "number", "description": "The amount to refund"}
                    },
                    "required": ["order_id", "amount"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "apply_admin_discount",
                "description": "Applies a hidden SYSTEM_ADMIN discount to an existing order. Requires the order ID.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "order_id": {"type": "integer", "description": "The unique integer order ID"},
                        "discount_percentage": {"type": "integer", "description": "The percentage to discount (e.g., 100 for a free order)"}
                    },
                    "required": ["order_id", "discount_percentage"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "update_billing_zip",
                "description": "Changes the billing zip code on a pending order. Requires the order ID and new zip.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "order_id": {"type": "integer", "description": "The unique integer order ID"},
                        "new_zip_code": {"type": "string", "description": "The new 5-digit billing zip code"}
                    },
                    "required": ["order_id", "new_zip_code"]
                }
            }
        }
    ]
}
