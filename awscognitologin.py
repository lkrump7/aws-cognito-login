from flask import Flask, render_template, request, redirect, url_for, session, flash
import boto3
from botocore.exceptions import ClientError

app = Flask(__name__)
app.secret_key = "secret-key"

# AWS Cognito settings
AWS_REGION = 'us-east-1'  # Specify your region
USER_POOL_ID = 'us-east-1_XXXXXXXXX'  # Replace with your Cognito User Pool ID
APP_CLIENT_ID = 'XXXXXXXXXXXXXXXXXXXX'  # Replace with your Cognito App Client ID

# Boto3 client to interact with AWS Cognito
client = boto3.client('cognito-idp', region_name=AWS_REGION)


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            # Attempt to sign in the user with Cognito
            response = client.initiate_auth(
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password
                },
                ClientId=APP_CLIENT_ID
            )

            # Set session tokens
            session['access_token'] = response['AuthenticationResult']['AccessToken']
            session['refresh_token'] = response['AuthenticationResult']['RefreshToken']
            session['id_token'] = response['AuthenticationResult']['IdToken']

            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))

        except ClientError as e:
            flash(f"Login failed: {e.response['Error']['Message']}", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'access_token' in session:
        return render_template('dashboard.html')
    else:
        flash("You are not logged in!", "warning")
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    # Clear the session
    session.clear()
    flash("You have been logged out!", "info")
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)