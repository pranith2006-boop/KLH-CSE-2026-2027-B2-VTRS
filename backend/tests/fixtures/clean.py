"""Safe counterparts for the local VulnTrack scanner demo."""
import ast
import json
import subprocess
import yaml


def inspect_input(source, command, yaml_text, user_id, cursor):
    ast.literal_eval(source)
    subprocess.run([command], check=True)
    yaml.safe_load(yaml_text)
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return json.loads('{"status": "ok"}')
