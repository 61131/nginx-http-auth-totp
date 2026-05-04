import pyotp
import argparse

parser = argparse.ArgumentParser(description="Generate a QR code to associate OTP apps")
parser.add_argument("secret")
parser.add_argument('-d', '--delay', type=int, nargs="?", default=30, help="Delay (in sec) before changing token")
parser.add_argument('-l', '--length', type=int, nargs='?', default=6, choices=[6,8], help="Number of digits in token")
args = parser.parse_args()

print(pyotp.TOTP(args.secret, digits = args.length, interval=args.delay).now( ))
