import pandas as pd

# Standard phishing vs legitimate email samples
data = {
    "Email Text": [
        "Dear customer, your bank account has been locked. Click here immediately to verify your identity: http://secure-bank-login.com/verify",
        "Hi Team, attached is the revised meeting agenda for our project sync tomorrow at 10 AM. Please review.",
        "URGENT: Your PayPal account is suspended! Update your billing credentials within 24 hours to avoid termination.",
        "Hey, are we still meeting for lunch today at 1 PM? Let me know.",
        "Congratulations! You won a $1,000 Walmart gift card. Claim your prize now by submitting your SSN and card details here: http://gift-rewards.xyz",
        "Reminder: The quarterly cybersecurity training module is due this Friday. Access the portal through the company intranet.",
        "Security Alert: Unusual sign-in attempt detected from Russia. Verify your password now or your account will be disabled: http://account-security-alert.net",
        "Please find the invoice for last month's cloud hosting services attached. Payment terms are net 30 days.",
        "Dear employee, your mailbox is full and you will stop receiving incoming emails. Re-authenticate your corporate email here: http://mail-update-sso.ru",
        "Can you send over the updated slides for the presentation? Need them before the client call.",
        "Final Notice: Your package could not be delivered due to unpaid customs fee of $2.99. Pay immediately: http://track-dhl-parcel.link",
        "Weekly engineering update: All pull requests for release v1.4 have been merged into the staging branch.",
        "Your Netflix subscription has expired. Click here to update your credit card details immediately to continue watching.",
        "The project documentation has been uploaded to the shared Google Drive folder. Let me know if you need access permissions.",
        "You have received an encrypted tax document from the IRS. Download the attachment and enable macros to view.",
        "Good morning, please remember to submit your weekly timesheets by end of day today.",
        "Action Required: Unrecognized wire transfer of $4,500.00 initiated. If this was not you, cancel the transaction immediately: http://fraud-prevention-alert.cc",
        "Thanks for sharing the notes. I will update the action items tracker accordingly.",
        "Exclusive offer! Click here to claim 50 free spins and instant cryptocurrency bonus on registration!",
        "Let's reschedule the sprint retrospective to Monday morning so everyone can attend."
    ] * 50,  # Multiplied to create 1,000 balanced rows for proper ML training
    "Email Type": [
        "Phishing Email", "Safe Email", "Phishing Email", "Safe Email",
        "Phishing Email", "Safe Email", "Phishing Email", "Safe Email",
        "Phishing Email", "Safe Email", "Phishing Email", "Safe Email",
        "Phishing Email", "Safe Email", "Phishing Email", "Safe Email",
        "Phishing Email", "Safe Email", "Phishing Email", "Safe Email"
    ] * 50
}

df = pd.DataFrame(data)
df.to_csv("emails.csv", index=False)
print(f"Successfully generated emails.csv with {len(df)} records!")