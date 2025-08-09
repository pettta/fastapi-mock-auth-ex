import argparse
import subprocess 

parser = argparse.ArgumentParser(description="Run local components")
parser.add_argument(
    "-v",
    "--variant",
    choices=['backend', 'oauth', 'frontend'],
    required=True,
    help="Which component to run: backend | oauth | frontend",
)
parser.add_argument(
    "-r",
    "--requirements_skip",
    action="store_true",
    help="Skip installing requirements"
)
args = parser.parse_args()

if not args.requirements_skip:
    subprocess.run(["pip", "install", "-r", "requirements.txt"])

if args.variant == 'frontend':
    subprocess.run(["python", "frontend.py"])
    exit() 

subprocess.run(["uvicorn", f"{args.variant}:app", "--reload"])