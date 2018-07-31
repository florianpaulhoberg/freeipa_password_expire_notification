#!/usr/bin/env python
# Copyright (c) 2018 Florian Paul Hoberg <florian.hoberg@credativ.de>

"""
    FreeIPA Password expire notificator - this script will check
    if passwords from users in directory will expire soon and
    notify them when needed.
"""

import datetime
import time
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import COMMASPACE, formatdate
from email import Encoders
from python_freeipa import Client


_IPA_PW_DAYS_LEST_ = 7
_IPA_EMAIL_FROM_ = "FreeIPA Service <no-reply@ipa01.hoberg-systems.ch>"
_IPA_HOST_ = "ipa01.hoberg-systems.ch"
_IPA_API_USER_ = "api-user"
_IPA_API_PW_ = "api-password"


def ipa_connect():
    """
        Connect and login to FreeIPA system with a secured
        SSL connection.
    """
    client = Client(_IPA_HOST_, version='2.215')
    client.login(_IPA_API_USER_, _IPA_API_PW_)
    return client


def ipa_fetch_user_attr(client):
    """
        Get all users from directory with an email address
        to be able to notify them.
    """
    ipa_users_emails = []
    ipa_users_notification = {}
    ipa_users_attr = client.user_find()
    for single_user in ipa_users_attr["result"]:
        if "mail" in single_user:
            ipa_user_mail = single_user["mail"][0]
            ipa_user_uid = single_user["uid"][0]
            ipa_users_emails.append(ipa_user_mail)
            for date in single_user["krbpasswordexpiration"]:
                ipa_user_password_expr = date["__datetime__"][:-7]
            ipa_users_notification[ipa_user_mail] = ipa_user_password_expr
    return ipa_users_emails, ipa_users_notification


def ipa_notify_user(ipa_notify_mails):
    """
        Generate password expire mail and send them via local MTA
        to make sure this'll be queued when remote MTA is unreachable.
    """
    server = "localhost"
    body = "Hello,\n this mail is to inform you that your password is going to expire within the next few days."
    msg = MIMEMultipart()
    msg['From'] = _IPA_EMAIL_FROM_
    msg['To'] = COMMASPACE.join(ipa_notify_mails)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = "FreeIPA: Your password will expire soon."
    msg.attach(MIMEText(body))
    smtp = smtplib.SMTP(server)
    smtp.sendmail(_IPA_EMAIL_FROM_, ipa_notify_mails, msg.as_string())
    smtp.close()


def ipa_pwexire_check(ipa_users_notification, ipa_users_emails):
    """
        Check if users password is going to expire within the
        next few days.
    """
    for single_user in ipa_users_emails:
        ipa_date_expr = ipa_users_notification[single_user]
        ipa_date_now = time.strftime("%Y%m%d")
        start_date = datetime.datetime.strptime(ipa_date_expr, "%Y%m%d")
        end_date = datetime.datetime.strptime(ipa_date_now, "%Y%m%d")
        ipa_days_left = abs((end_date-start_date).days)
        if ipa_days_left < _IPA_PW_DAYS_LEST_:
            ipa_notify_mails = []
            ipa_notify_mails.append(single_user)
            ipa_notify_user(ipa_notify_mails)


def main():
    """
        Run the main programm
    """
    client = ipa_connect()
    ipa_users_emails, ipa_users_notification = ipa_fetch_user_attr(client)
    ipa_pwexire_check(ipa_users_notification, ipa_users_emails)


main()
