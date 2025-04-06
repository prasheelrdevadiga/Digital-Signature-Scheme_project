from flask import Flask, render_template, request, redirect, url_for, session
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import difflib

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/sign', methods=['POST'])
def sign():
    message = request.form['message'].encode()
    sender = request.form['sender']
    recipient = request.form['recipient']

    private_key = dsa.generate_private_key(key_size=2048)
    public_key = private_key.public_key()
    signature = private_key.sign(message, hashes.SHA256())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, sender),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        public_key
    ).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(private_key, hashes.SHA256())

    session['message'] = message.decode()
    session['signature'] = signature.hex()
    session['public_key'] = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    session['certificate'] = cert.public_bytes(serialization.Encoding.PEM).decode()
    session['sender'] = sender
    session['recipient'] = recipient
    session['private_key'] = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode()

    return redirect(url_for('signed_details'))

@app.route('/signed-details')
def signed_details():
    return render_template(
        'signed_details.html',
        message=session['message'],
        signature=session['signature'],
        public_key=session['public_key'],
        certificate=session['certificate'],
        sender=session['sender'],
        recipient=session['recipient']
    )

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        message = session.get('message', '').encode()
        signature = bytes.fromhex(session.get('signature'))
        public_key = serialization.load_pem_public_key(session['public_key'].encode())

        try:
            public_key.verify(signature, message, hashes.SHA256())
            result = '✅ Signature is valid. Sender is trusted based on X.509 certificate.'
        except Exception as e:
            result = f'❌ Signature verification failed: {str(e)}'

        return render_template(
            'result.html',
            result=result,
            original_message=session['message'],
            original_signature=session['signature'],
            used_message=session['message'],
            used_signature=session['signature'],
            public_key=session['public_key'],
            certificate=session['certificate'],
            differences=None
        )

    return render_template('verify.html', message=session['message'], public_key=session['public_key'])

@app.route('/mitm', methods=['GET', 'POST'])
def mitm():
    if request.method == 'POST':
        original_message = session.get('message', '')
        tampered_message = request.form['tampered_message']
        public_key_pem = session.get('public_key')
        original_signature = bytes.fromhex(session.get('signature'))
        original_cert = x509.load_pem_x509_certificate(session['certificate'].encode())

        # Simulate attacker signing same/different message with their own private key
        attacker_private_key = dsa.generate_private_key(key_size=2048)
        attacker_public_key = attacker_private_key.public_key()
        fake_signature = attacker_private_key.sign(tampered_message.encode(), hashes.SHA256())

        # Create attacker's certificate
        attacker_cert = x509.CertificateBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FakeOrg"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"Attacker"),
        ])).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FakeOrg"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"Attacker"),
        ])).public_key(attacker_public_key
        ).serial_number(x509.random_serial_number()
        ).not_valid_before(datetime.datetime.utcnow()
        ).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).sign(attacker_private_key, hashes.SHA256())

        # Try verifying attacker's signature using original public key
        try:
            original_public_key = serialization.load_pem_public_key(public_key_pem.encode())
            original_public_key.verify(fake_signature, tampered_message.encode(), hashes.SHA256())
            # Now check if the attacker certificate and original are same
            if attacker_cert.subject != original_cert.subject:
                result = "❌ Signature is valid but sender is NOT trusted. Certificate mismatch (MITM detected)."
            else:
                result = "✅ Signature is valid and sender is trusted."
        except Exception:
            result = "❌ Signature verification failed due to tampering."

        return render_template(
            'result.html',
            result=result,
            original_message=original_message,
            used_message=tampered_message,
            original_signature=session['signature'],
            used_signature=fake_signature.hex(),
            public_key=public_key_pem,
            certificate=attacker_cert.public_bytes(serialization.Encoding.PEM).decode(),
            differences=None
        )

    return render_template('mitm.html', public_key=session['public_key'])



if __name__ == '__main__':
    app.run(debug=True)
