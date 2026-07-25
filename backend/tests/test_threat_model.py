from aegis.schemas.attack_surface import AttackSurfaceFile
from aegis.security.threat_model import ThreatModeler


def test_threat_modeler_builds_deterministic_threats() -> None:
    files = [
        AttackSurfaceFile(
            filename="app.py",
            language="python",
            code="""
import os
import requests

def run_command(command: str):
    return os.system(command)

def find_user(db, user_id: str):
    return db.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    ).fetchone()

def fetch_url(request):
    url = request.args.get("url")
    return requests.get(url)
""".strip(),
        ),
    ]

    result = ThreatModeler().scan(files)

    categories = {
        threat.category
        for threat in result.threats
    }

    assert "command_injection" in categories
    assert "sql_injection" in categories
    assert "ssrf" in categories
    assert "unsafe_data_flow" in categories

    assert result.summary.files_scanned == 1
    assert result.summary.threats_found == len(
        result.threats
    )
    assert result.summary.critical >= 1
    assert result.summary.high >= 2

    assert result.assets
    assert result.trust_boundaries


def test_threat_ids_are_stable() -> None:
    files = [
        AttackSurfaceFile(
            filename="worker.py",
            language="python",
            code="""
import subprocess

def run_job(name: str):
    return subprocess.run(
        ["worker", name],
        check=True,
    )
""".strip(),
        ),
    ]

    modeler = ThreatModeler()

    first = modeler.scan(files)
    second = modeler.scan(files)

    assert [
        threat.id
        for threat in first.threats
    ] == [
        threat.id
        for threat in second.threats
    ]


def test_empty_supported_surface_returns_empty_model() -> None:
    files = [
        AttackSurfaceFile(
            filename="plain.py",
            language="python",
            code="""
def add(left: int, right: int) -> int:
    return left + right
""".strip(),
        ),
    ]

    result = ThreatModeler().scan(files)

    assert result.threats == []
    assert result.assets == []
    assert result.trust_boundaries == []
    assert result.summary.threats_found == 0


def test_safe_sensitive_operations_are_not_threats() -> None:
    files = [
        AttackSurfaceFile(
            filename="safe.py",
            language="python",
            code="""
import os
import subprocess
import requests


def run_job(job_name: str):
    return subprocess.run(
        ["worker", job_name],
        check=True,
    )


def load_user(db, user_id: str):
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(
        query,
        (user_id,),
    ).fetchone()


def load_secret():
    return os.environ["APP_API_KEY"]


def fetch_status():
    return requests.get(
        "https://status.example.com/health"
    )
""".strip(),
        ),
    ]

    result = ThreatModeler().scan(files)

    categories = {
        threat.category
        for threat in result.threats
    }

    assert "command_injection" not in categories
    assert "sql_injection" not in categories
    assert "secret_exposure" not in categories
    assert "ssrf" not in categories


def test_secret_logging_is_reported() -> None:
    files = [
        AttackSurfaceFile(
            filename="leak.py",
            language="python",
            code="""
import os


def debug_secret():
    api_key = os.environ["APP_API_KEY"]
    print(api_key)
""".strip(),
        ),
    ]

    result = ThreatModeler().scan(files)

    assert any(
        threat.category == "secret_exposure"
        for threat in result.threats
    )



def test_detected_threats_receive_exploitability_classification() -> None:
    files = [
        AttackSurfaceFile(
            filename="app.py",
            language="python",
            code="""
import os


def run_command(command: str):
    return os.system(command)
""".strip(),
        ),
    ]

    result = ThreatModeler().scan(files)

    assert result.threats

    threat = result.threats[0]

    assert threat.exploitability == "confirmed"
    assert threat.exploitability_confidence >= 0.9
    assert threat.exploitability_reasons
    assert threat.prerequisites
    assert threat.blocking_controls == []



def test_command_injection_is_classified_as_confirmed() -> None:
    files = [
        AttackSurfaceFile(
            filename="command.py",
            language="python",
            code="""
import os


def execute(request):
    command = request.args.get("command")
    return os.system(command)
""".strip(),
        ),
    ]

    result = ThreatModeler().scan(files)

    threat = next(
        threat
        for threat in result.threats
        if threat.category == "command_injection"
    )

    assert threat.exploitability == "confirmed"
    assert threat.exploitability_confidence >= 0.9
    assert threat.exploitability_reasons
    assert threat.prerequisites
    assert threat.blocking_controls == []


def test_dynamic_sql_parameter_flow_is_confirmed() -> None:
    files = [
        AttackSurfaceFile(
            filename="database.py",
            language="python",
            code="""
def lookup(db, username):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return db.execute(query).fetchone()
""".strip(),
        ),
    ]

    result = ThreatModeler().scan(files)

    threat = next(
        threat
        for threat in result.threats
        if threat.category == "sql_injection"
    )

    assert threat.exploitability == "confirmed"
    assert threat.exploitability_confidence >= 0.9
    assert any(
        "source-to-sink data-flow edge proves"
        in reason.lower()
        for reason in threat.exploitability_reasons
    )
    assert threat.prerequisites


def test_ssrf_with_request_input_is_likely() -> None:
    files = [
        AttackSurfaceFile(
            filename="ssrf.py",
            language="python",
            code="""
import requests


def fetch(request):
    url = request.args.get("url")
    return requests.get(url)
""".strip(),
        ),
    ]

    result = ThreatModeler().scan(files)

    threat = next(
        threat
        for threat in result.threats
        if threat.category == "ssrf"
    )

    assert threat.exploitability == "likely"
    assert threat.exploitability_confidence >= 0.9
    assert threat.exploitability_reasons
    assert threat.prerequisites


def test_secret_logging_is_confirmed() -> None:
    files = [
        AttackSurfaceFile(
            filename="secret.py",
            language="python",
            code="""
import os


def leak():
    token = os.environ["APP_TOKEN"]
    print(token)
""".strip(),
        ),
    ]

    result = ThreatModeler().scan(files)

    threat = next(
        threat
        for threat in result.threats
        if threat.category == "secret_exposure"
    )

    assert threat.exploitability == "confirmed"
    assert threat.exploitability_confidence >= 0.9
    assert threat.exploitability_reasons
    assert threat.prerequisites


def test_unsafe_data_flow_is_possible() -> None:
    files = [
        AttackSurfaceFile(
            filename="flow.py",
            language="python",
            code="""
import requests


def forward(request):
    target = request.args.get("target")
    return requests.get(target)
""".strip(),
        ),
    ]

    result = ThreatModeler().scan(files)

    threat = next(
        threat
        for threat in result.threats
        if threat.category == "unsafe_data_flow"
    )

    assert threat.exploitability == "possible"
    assert threat.exploitability_confidence >= 0.7
    assert threat.exploitability_reasons
    assert threat.prerequisites



def test_typescript_exec_template_parameter_is_confirmed() -> None:
    files = [
        AttackSurfaceFile(
            filename="command.ts",
            language="typescript",
            code="""
import { exec } from "node:child_process";


function pingHost(input: string) {
    return exec(`ping -c 1 ${input}`);
}
""".strip(),
        ),
    ]

    result = ThreatModeler().scan(files)

    threat = next(
        threat
        for threat in result.threats
        if threat.category == "command_injection"
    )

    assert threat.exploitability == "confirmed"
    assert threat.exploitability_confidence >= 0.9
    assert any(
        "source-to-sink data-flow edge proves"
        in reason.lower()
        for reason in threat.exploitability_reasons
    )


def test_python_intermediate_command_variable_is_confirmed() -> None:
    files = [
        AttackSurfaceFile(
            filename="command.py",
            language="python",
            code="""
import os


def ping_host(host):
    command = f"ping -c 1 {host}"
    return os.system(command)
""".strip(),
        ),
    ]

    result = ThreatModeler().scan(files)

    threat = next(
        threat
        for threat in result.threats
        if threat.category == "command_injection"
    )

    assert threat.exploitability == "confirmed"
    assert threat.exploitability_confidence >= 0.9


def test_sql_parameter_binding_is_a_blocking_control() -> None:
    controls = ThreatModeler._detect_blocking_controls(
        category="sql_injection",
        context="""
def lookup(db, username):
    return db.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,),
    )
""".strip(),
    )

    assert controls
    assert any(
        "parameter binding" in control.lower()
        for control in controls
    )

    exploitability, confidence = (
        ThreatModeler._downgrade_for_blocking_controls(
            exploitability="likely",
            confidence=0.85,
        )
    )

    assert exploitability == "unlikely"
    assert confidence >= 0.84


def test_path_root_containment_is_a_blocking_control() -> None:
    controls = ThreatModeler._detect_blocking_controls(
        category="path_traversal",
        context="""
import os


BASE_DIR = "/srv/uploads"


def read_file(filename):
    candidate = os.path.realpath(
        os.path.join(BASE_DIR, filename)
    )
    root = os.path.realpath(BASE_DIR) + os.sep

    if not candidate.startswith(root):
        raise ValueError("invalid path")

    return open(candidate).read()
""".strip(),
    )

    assert len(controls) >= 2
    assert any(
        "canonicalized" in control.lower()
        for control in controls
    )
    assert any(
        "allowed root" in control.lower()
        for control in controls
    )

    exploitability, confidence = (
        ThreatModeler._downgrade_for_blocking_controls(
            exploitability="likely",
            confidence=0.89,
        )
    )

    assert exploitability == "unlikely"
    assert confidence >= 0.84


def test_ssrf_host_allowlist_is_a_blocking_control() -> None:
    controls = ThreatModeler._detect_blocking_controls(
        category="ssrf",
        context="""
from urllib.parse import urlparse


ALLOWED_HOSTS = {"api.example.com"}


def validate_target(target):
    hostname = urlparse(target).hostname

    if hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
""".strip(),
    )

    assert len(controls) >= 2
    assert any(
        "allowlist" in control.lower()
        for control in controls
    )
    assert any(
        "hostname is parsed" in control.lower()
        for control in controls
    )

    exploitability, confidence = (
        ThreatModeler._downgrade_for_blocking_controls(
            exploitability="likely",
            confidence=0.91,
        )
    )

    assert exploitability == "unlikely"
    assert confidence >= 0.84


def test_shell_false_argument_list_is_a_blocking_control() -> None:
    controls = ThreatModeler._detect_blocking_controls(
        category="command_injection",
        context="""
import subprocess


def ping(host):
    return subprocess.run(
        ["ping", "-c", "1", host],
        shell=False,
        check=True,
    )
""".strip(),
    )

    assert len(controls) == 2
    assert any(
        "argument list" in control.lower()
        for control in controls
    )
    assert any(
        "disabled" in control.lower()
        for control in controls
    )


def test_unrelated_shell_control_does_not_protect_sink() -> None:
    context = """
import os
import subprocess


def safe_ping(host):
    return subprocess.run(
        ["ping", "-c", "1", host],
        shell=False,
    )


def vulnerable(command):
    return os.system(command)
""".strip()

    controls = ThreatModeler._detect_blocking_controls(
        category="command_injection",
        context=context,
        evidence="return os.system(command)",
    )

    assert controls == []


def test_shell_control_is_detected_for_its_own_sink() -> None:
    context = """
import subprocess


def safe_ping(host):
    return subprocess.run(
        ["ping", "-c", "1", host],
        shell=False,
    )
""".strip()

    controls = ThreatModeler._detect_blocking_controls(
        category="command_injection",
        context=context,
        evidence=(
            'return subprocess.run('
        ),
    )

    assert len(controls) == 2
    assert any(
        "argument list" in control.lower()
        for control in controls
    )
    assert any(
        "disabled" in control.lower()
        for control in controls
    )


def test_unrelated_ssrf_allowlist_does_not_protect_sink() -> None:
    context = """
from urllib.parse import urlparse
import requests


ALLOWED_HOSTS = {"api.example.com"}


def validated_fetch(target):
    hostname = urlparse(target).hostname

    if hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")

    return requests.get(target)


def vulnerable_fetch(target):
    return requests.get(target)
""".strip()

    controls = ThreatModeler._detect_blocking_controls(
        category="ssrf",
        context=context,
        evidence="return requests.get(target)",
    )

    assert controls == []


def test_ssrf_allowlist_is_detected_for_its_own_sink() -> None:
    context = """
from urllib.parse import urlparse
import requests


ALLOWED_HOSTS = {"api.example.com"}


def validated_fetch(target):
    hostname = urlparse(target).hostname

    if hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")

    return requests.get(target)
""".strip()

    controls = ThreatModeler._detect_blocking_controls(
        category="ssrf",
        context=context,
        evidence="return requests.get(target)",
    )

    assert len(controls) >= 2
    assert any(
        "allowlist" in control.lower()
        for control in controls
    )
    assert any(
        "hostname is parsed" in control.lower()
        for control in controls
    )


def test_command_injection_reason_uses_proven_data_flow() -> None:
    files = [
        AttackSurfaceFile(
            filename="command.py",
            language="python",
            code="""
import os


def execute(request):
    raw_command = request.args.get("command")
    command = raw_command.strip()
    return os.system(command)
""".strip(),
        ),
    ]

    result = ThreatModeler().scan(files)

    threat = next(
        threat
        for threat in result.threats
        if threat.category == "command_injection"
    )

    assert threat.exploitability == "confirmed"
    assert any(
        "source-to-sink data-flow edge proves"
        in reason.lower()
        for reason in threat.exploitability_reasons
    )

    assert any(
        edge.target in threat.source_node_ids
        and edge.relationship == "data_flow"
        for edge in result.attack_surface_edges
    )


def test_ssrf_graph_proof_raises_confidence() -> None:
    files = [
        AttackSurfaceFile(
            filename="ssrf.py",
            language="python",
            code="""
import requests


def fetch(request):
    raw_url = request.args.get("url")
    target = raw_url.strip()
    return requests.get(target)
""".strip(),
        ),
    ]

    result = ThreatModeler().scan(files)

    threat = next(
        threat
        for threat in result.threats
        if threat.category == "ssrf"
    )

    assert threat.exploitability == "likely"
    assert threat.exploitability_confidence >= 0.95
    assert any(
        "source-to-sink data-flow edge proves"
        in reason.lower()
        for reason in threat.exploitability_reasons
    )


def test_unrelated_nearby_input_is_not_graph_proof() -> None:
    files = [
        AttackSurfaceFile(
            filename="network.py",
            language="python",
            code="""
import requests


def fetch(request):
    ignored = request.args.get("url")
    target = "https://api.example.com"
    return requests.get(target)
""".strip(),
        ),
    ]

    result = ThreatModeler().scan(files)

    threat = next(
        threat
        for threat in result.threats
        if threat.category == "ssrf"
    )

    assert not any(
        "source-to-sink data-flow edge proves"
        in reason.lower()
        for reason in threat.exploitability_reasons
    )

    assert not any(
        edge.relationship == "data_flow"
        for edge in result.attack_surface_edges
    )


def test_threat_contains_complete_data_flow_path() -> None:
    files = [
        AttackSurfaceFile(
            filename="ssrf.py",
            language="python",
            code="""
import requests


def fetch(request):
    raw_url = request.args.get("url")
    target = raw_url.strip()
    return requests.get(target)
""".strip(),
        ),
    ]

    result = ThreatModeler().scan(files)

    threat = next(
        threat
        for threat in result.threats
        if threat.category == "ssrf"
    )

    assert threat.data_flow == [
        'request.args.get("url")',
        "raw_url",
        "target",
        "return requests.get(target)",
    ]

    assert len(threat.source_node_ids) >= 2

    flow_edges = [
        edge
        for edge in result.attack_surface_edges
        if edge.relationship == "data_flow"
        and edge.target in threat.source_node_ids
    ]

    assert flow_edges
    assert all(
        edge.source in threat.source_node_ids
        for edge in flow_edges
    )


def test_threat_without_graph_proof_has_empty_data_flow() -> None:
    files = [
        AttackSurfaceFile(
            filename="network.py",
            language="python",
            code="""
import requests


def fetch(request):
    ignored = request.args.get("url")
    target = "https://api.example.com"
    return requests.get(target)
""".strip(),
        ),
    ]

    result = ThreatModeler().scan(files)

    threat = next(
        threat
        for threat in result.threats
        if threat.category == "ssrf"
    )

    assert threat.data_flow == []


def test_multiline_filesystem_flow_is_exposed() -> None:
    files = [
        AttackSurfaceFile(
            filename="files.ts",
            language="typescript",
            code="""
export function loadFile(filename: string): string {
  return fs.readFileSync(
    path.join("/srv/uploads", filename),
    "utf8",
  );
}
""".strip(),
        ),
    ]

    result = ThreatModeler().scan(files)

    threat = next(
        threat
        for threat in result.threats
        if threat.category == "path_traversal"
    )

    assert threat.data_flow == [
        "filename",
        'path.join("/srv/uploads", filename)',
        "fs.readFileSync(...)",
    ]

    sink = next(
        node
        for node in result.attack_surface_nodes
        if node.kind == "filesystem"
    )

    assert sink.line_start == 2
    assert sink.line_end == 5


def test_builds_process_input_trust_boundary_from_proven_flow() -> None:
    result = ThreatModeler().scan(
        [
            AttackSurfaceFile(
                filename="command.py",
                language="python",
                code="""
import subprocess


def run_command(user_input: str) -> None:
    subprocess.run(
        user_input,
        shell=True,
    )
""".strip(),
            )
        ]
    )

    boundary = next(
        boundary
        for boundary in result.trust_boundaries
        if boundary.boundary_type
        == "untrusted_process_input"
    )

    assert boundary.label == (
        "Untrusted input to operating-system process"
    )
    assert len(boundary.source_node_ids) == 2
    assert (
        result.summary.trust_boundaries_found
        == len(result.trust_boundaries)
    )
    assert result.summary.trust_boundaries_found >= 1


def test_safe_parameters_do_not_create_process_boundaries() -> None:
    result = ThreatModeler().scan(
        [
            AttackSurfaceFile(
                filename="safe.py",
                language="python",
                code="""
def add(left: int, right: int) -> int:
    return left + right
""".strip(),
            )
        ]
    )

    assert result.trust_boundaries == []
    assert (
        result.summary.trust_boundaries_found
        == 0
    )
