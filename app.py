import os
import base64
import os
from flask import Flask, request, jsonify, Response, render_template
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json
)
from webauthn.helpers.structs import (
    AuthenticatorAttachment, 
    UserVerificationRequirement,
    ResidentKeyRequirement,
    AuthenticatorSelectionCriteria
)
from webauthn.helpers.structs import (
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)
#from webauthn.helpers.structs import RegistrationCredential
from webauthn.helpers import (
    parse_authentication_credential_json,
    parse_registration_credential_json
)

app = Flask(__name__, template_folder='.')
app.secret_key = os.urandom(32)

# -----------------------------
# Configuration
# -----------------------------
RP_ID = "localhost"
RP_NAME =  "My WebAuthn App"
ORIGIN = "http://localhost:3000"
# This simulates the database.
# However, in real applications, you must use a database.
db = {
    "users": {}  
}

@app.route('/')
def index():
    try:
        return render_template('index.html')
    except Exception as e:
        return f"Error: index.html not found in templates folder. {str(e)}", 404
  
# -----------------------------
# Begin PassKey Registration
# -----------------------------
@app.route("/register/begin", methods=["POST"])
def register_begin():
    try:

        #Get the user name from the web browser
        username = request.json.get("username")
        # Create a unique ID for the user if they don't exist
        if username not in db["users"]:
            user_id= os.urandom(32)
            # The real applications require you to use a database to store it
            db["users"][username] = {"user_id": user_id}
        else :
            print("ERROR: This user is alredy exsits!!")
            return jsonify({"status": "error", "message": "User already Exsits"}), 500
       
        # Generate the user registration options
        registration_options = generate_registration_options(
            rp_id=RP_ID,
            rp_name=RP_NAME,
            user_id=user_id,
            user_name=username,
            user_display_name=username,
            authenticator_selection=AuthenticatorSelectionCriteria(
                #This triggers where the keys will be stored.'
                resident_key=ResidentKeyRequirement.PREFERRED,
                #This triggers the "Use the platform device'
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                #This triggers the "Use a different device'
                #authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
                user_verification=UserVerificationRequirement.REQUIRED
            )
        )

        #Save the user registration options in the database
        db["users"][username]["reg_state"] = registration_options
        
        #Send the registration options to the browser as a JSON object 
        json_data = options_to_json(registration_options)
        return Response(json_data, mimetype='application/json')
        
    except Exception as e:
        print(f"!!! SERVER CRASH: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500
    
# -------------------------------
# Complete the User Registration
# -------------------------------
@app.route("/register/complete", methods=["POST"])
def register_complete():
    try:
        data = request.json
        username = data.get("username")

        # Check if this user has already started the registration. If not, return an error
        if username not in db["users"]:  
            return jsonify({"status": "error", "message": "No registration in progress"}), 500

        # Parse the incoming JSON into a Credential object
        credential = parse_registration_credential_json(data.get("credential"))
        
        # Retrieve the state we saved in the database
        expected_state = db["users"][username]["reg_state"]

        # CRITICAL: Verify the cryptographic signature
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=expected_state.challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID
        )

        # Success! Save the Public Key and Credential ID in the database
        # You should set the sign count to be zero 
        db["users"][username]["public_key"] = verification.credential_public_key
        db["users"][username]["credential_id"] = verification.credential_id
        db["users"][username]["sign_count"] = 0
        
        print(f"[*] REGISTERED: {username} (ID: {verification.credential_id.hex()[:10]}...)")
        return jsonify({"status": "success", "message": "TouchID Verified & Key Saved!"})

    except Exception as e:
        print(f"!!! Verification Failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400


# -----------------------------------------------------------------
# Start the login process by sending the challenge to the browser
# -----------------------------------------------------------------
@app.route('/api/generate-login-challenge', methods=['POST'])
def generate_login_challenge():
    try:
        username = request.json.get("username")
        user = db["users"].get(username)
       
        # Check if this user has already started the registration. If not, return an error
        if not user: 
            return jsonify({"status": "error", "message": "The user does not exist"}), 400

        allowed_creds = [
            PublicKeyCredentialDescriptor(id=user["credential_id"])
        ]
        
        # Generate the challenges to be sent to the browser
        options = generate_authentication_options(
            rp_id=RP_ID,
            allow_credentials=allowed_creds,
            user_verification=UserVerificationRequirement.REQUIRED
        )
        
        # Save the challenge in the database
        db["users"][username]["auth_state"] = options.challenge

        # Send the JSON object to the browser with the challenge
        return jsonify({
            "challenge": base64.urlsafe_b64encode(options.challenge).decode().replace('=', ''),
            "allowCredentials": [{
                "id": base64.urlsafe_b64encode(user["credential_id"]).decode().replace('=', ''),
                "type": "public-key",
                #This triggers the "Use a different device'
                #"transports": ["hybrid", "usb", "ble", "nfc"]
                # This tells the Mac to use TouchID/Passkey
                "transports": ["internal"] 
            }],
            "userVerification": "required",
            "rpId": RP_ID
        })
    
    except Exception as e:
        print(f"!!! Verification Initiation Failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400


# -----------------------------------------------------------------
# Complete the login by verifying the signature of the challenge
# -----------------------------------------------------------------
@app.route('/api/login-verify', methods=['POST'])
def login_verify():
    try:
        data = request.json
        username = data.get("username")
        user = db["users"].get(username)
        
        # Retrieve the credential object received from the client
        credential = parse_authentication_credential_json(data["credential"])
        
        # Verify the digital signature of the credential
        verification = verify_authentication_response(credential=credential,
                    expected_challenge=user["auth_state"],
                    expected_rp_id=RP_ID, 
                    expected_origin=ORIGIN,
                    credential_public_key=user["public_key"],
                    credential_current_sign_count=user["sign_count"]
                    )
        # Save the sign count in the database to prevent the replay attack
        # It is always zero for some hardware.
        db["users"][username]["sign_count"] = verification.new_sign_count
        print(f"Updated sign_count for {username} to {verification.new_sign_count}")

        return jsonify({"status": "success", "message": "Successfully Logged in!"}),500
   
    except Exception as e:
        print(f"!!! Verification Failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400


# -----------------------------
# Run the Application
# -----------------------------
if __name__ == '__main__':
    print("--------------------------------------------------")
    print("WebAuthn Lab Server running at http://localhost:3000")
    print("Note: WebAuthn requires a Secure Context (localhost is allowed).")
    print("--------------------------------------------------")
    app.run(debug=True,host="localhost",port=3000)
