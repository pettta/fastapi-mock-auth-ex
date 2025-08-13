import argparse
import subprocess 
import platform

is_apple = platform.system() != "Windows"

parser = argparse.ArgumentParser(description="Run local components")
parser.add_argument(
    "-v",
    "--variant",
    choices=['backend', 'backend2', 'backend3', 'oauth', 'frontend'],
    required=True,
    help="Which component to run: backend | backend2 | backend3 | oauth | frontend",
)
parser.add_argument(
    "-r",
    "--requirements_skip",
    action="store_true",
    help="Skip installing requirements"
)
args = parser.parse_args()

if not args.requirements_skip:
    processArgs = ["python", "-m", "pip", "install", "-r", "requirements.txt"] if is_apple else ["pip", "install", "-r", "requirements.txt"]
    subprocess.run(processArgs)

if args.variant == 'frontend':
    subprocess.run(["python", "frontend.py"])
    exit() 

port=9000 if 'backend' in args.variant else 9001

subprocess.run(["uvicorn", f"{args.variant}:app", "--reload", "--host", "0.0.0.0", "--port", str(port)])