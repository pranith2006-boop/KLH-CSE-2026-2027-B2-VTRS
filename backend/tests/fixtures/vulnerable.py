"""Intentionally unsafe patterns for the local VulnTrack scanner demo."""
import pickle
import subprocess
import yaml


def inspect_payload(source, command, serialized, yaml_text, user_id, cursor):
    eval(source)
    exec(source)
    subprocess.run(command, shell=True)
    pickle.loads(serialized)
    yaml.load(yaml_text)
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
