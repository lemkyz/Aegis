from aegis.schemas.attack_surface import (
    AttackSurfaceFile,
)
from aegis.security.attack_surface import (
    AttackSurfaceMapper,
)


def test_maps_python_fastapi_surface() -> None:
    mapper = AttackSurfaceMapper()

    result = mapper.scan(
        [
            AttackSurfaceFile(
                filename="api.py",
                language="python",
                code="""
from fastapi import Depends, FastAPI
import os
import requests
import subprocess

app = FastAPI()

@app.post("/users/{user_id}")
def update_user(
    user_id: str,
    current_user=Depends(require_auth),
):
    token = os.getenv("SERVICE_TOKEN")
    db.execute(
        "UPDATE users SET active = 1 WHERE id = ?",
        (user_id,),
    )
    requests.post("https://audit.example/events")
    subprocess.run(["echo", user_id])
    return {"ok": True}
""".strip(),
            )
        ]
    )

    kinds = {
        node.kind
        for node in result.nodes
    }

    assert "http_route" in kinds
    assert "authentication" in kinds
    assert "database" in kinds
    assert "outbound_request" in kinds
    assert "process_execution" in kinds
    assert "secret_access" in kinds

    route = next(
        node
        for node in result.nodes
        if node.kind == "http_route"
    )

    assert route.method == "POST"
    assert route.path == "/users/{user_id}"
    assert route.authenticated is True

    assert result.summary.routes == 1
    assert result.summary.authenticated_routes == 1
    assert result.summary.process_executions == 1

    assert any(
        edge.source == route.id
        and edge.relationship
        == "route_reaches_database"
        for edge in result.edges
    )


def test_maps_express_unauthenticated_route() -> None:
    mapper = AttackSurfaceMapper()

    result = mapper.scan(
        [
            AttackSurfaceFile(
                filename="server.js",
                language="javascript",
                code="""
const fs = require("fs");
const { exec } = require("child_process");

app.get("/download/:name", (req, res) => {
  const name = req.params.name;
  const content = fs.readFileSync("./data/" + name);
  exec("audit " + name);
  res.send(content);
});
""".strip(),
            )
        ]
    )

    route = next(
        node
        for node in result.nodes
        if node.kind == "http_route"
    )

    assert route.method == "GET"
    assert route.path == "/download/:name"
    assert route.authenticated is False
    assert route.risk == "high"

    assert result.summary.filesystems == 1
    assert result.summary.process_executions == 1
    assert result.summary.unauthenticated_routes == 1


def test_ignores_unsupported_language() -> None:
    mapper = AttackSurfaceMapper()

    result = mapper.scan(
        [
            AttackSurfaceFile(
                filename="main.go",
                language="go",
                code='fmt.Println("hello")',
            )
        ]
    )

    assert result.nodes == []
    assert result.edges == []
    assert result.summary.nodes_found == 0


def test_traces_python_local_source_to_sink_flow() -> None:
    flow = AttackSurfaceMapper._trace_local_data_flow(
        code="""
def fetch(request):
    raw_url = request.args.get("url")
    target = raw_url.strip()
    return requests.get(target)
""".strip(),
        source_expression='request.args.get("url")',
        sink_expression="requests.get(target)",
    )

    assert flow == [
        'request.args.get("url")',
        "raw_url",
        "target",
        "requests.get(target)",
    ]


def test_traces_javascript_local_source_to_sink_flow() -> None:
    flow = AttackSurfaceMapper._trace_local_data_flow(
        code="""
function fetchTarget(req) {
  const raw = req.query.url;
  const target = raw.trim();
  return fetch(target);
}
""".strip(),
        source_expression="req.query.url",
        sink_expression="fetch(target)",
    )

    assert flow == [
        "req.query.url",
        "raw",
        "target",
        "fetch(target)",
    ]


def test_does_not_trace_unrelated_value_to_sink() -> None:
    flow = AttackSurfaceMapper._trace_local_data_flow(
        code="""
def fetch(request):
    raw_url = request.args.get("url")
    target = "https://api.example.com"
    return requests.get(target)
""".strip(),
        source_expression='request.args.get("url")',
        sink_expression="requests.get(target)",
    )

    assert flow == []


def test_builds_python_data_flow_edge() -> None:
    mapper = AttackSurfaceMapper()

    result = mapper.scan(
        [
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
            )
        ]
    )

    source = next(
        node
        for node in result.nodes
        if node.kind == "user_input"
    )
    sink = next(
        node
        for node in result.nodes
        if node.kind == "outbound_request"
    )

    edge = next(
        edge
        for edge in result.edges
        if edge.source == source.id
        and edge.target == sink.id
        and edge.relationship == "data_flow"
    )

    assert edge.confidence >= 0.84
    assert result.summary.edges_found == len(
        result.edges
    )


def test_builds_javascript_data_flow_edge() -> None:
    mapper = AttackSurfaceMapper()

    result = mapper.scan(
        [
            AttackSurfaceFile(
                filename="command.js",
                language="javascript",
                code="""
const { exec } = require("child_process");


function run(req) {
  const raw = req.query.command;
  const command = raw.trim();
  return exec(command);
}
""".strip(),
            )
        ]
    )

    source = next(
        node
        for node in result.nodes
        if node.kind == "user_input"
    )
    sink = next(
        node
        for node in result.nodes
        if node.kind == "process_execution"
    )

    assert any(
        edge.source == source.id
        and edge.target == sink.id
        and edge.relationship == "data_flow"
        and edge.confidence >= 0.84
        for edge in result.edges
    )


def test_does_not_build_data_flow_edge_for_safe_constant() -> None:
    mapper = AttackSurfaceMapper()

    result = mapper.scan(
        [
            AttackSurfaceFile(
                filename="safe.py",
                language="python",
                code="""
import requests


def fetch(request):
    raw_url = request.args.get("url")
    target = "https://api.example.com"
    return requests.get(target)
""".strip(),
            )
        ]
    )

    assert not any(
        edge.relationship == "data_flow"
        for edge in result.edges
    )


def test_builds_python_parameter_to_process_edge() -> None:
    mapper = AttackSurfaceMapper()

    result = mapper.scan(
        [
            AttackSurfaceFile(
                filename="command.py",
                language="python",
                code="""
import os


def ping_host(host):
    command = f"ping -c 1 {host}"
    return os.system(command)
""".strip(),
            )
        ]
    )

    source = next(
        node
        for node in result.nodes
        if node.kind == "function_parameter"
        and node.symbol == "host"
    )
    sink = next(
        node
        for node in result.nodes
        if node.kind == "process_execution"
    )

    edge = next(
        edge
        for edge in result.edges
        if edge.source == source.id
        and edge.target == sink.id
        and edge.relationship == "data_flow"
    )

    assert edge.confidence >= 0.84


def test_builds_javascript_parameter_to_sql_edge() -> None:
    mapper = AttackSurfaceMapper()

    result = mapper.scan(
        [
            AttackSurfaceFile(
                filename="database.js",
                language="javascript",
                code="""
function findUser(db, username) {
  return db.query(`SELECT * FROM users WHERE username = '${username}'`);
}
""".strip(),
            )
        ]
    )

    source = next(
        node
        for node in result.nodes
        if node.kind == "function_parameter"
        and node.symbol == "username"
    )
    sink = next(
        node
        for node in result.nodes
        if node.kind == "database"
    )

    assert any(
        edge.source == source.id
        and edge.target == sink.id
        and edge.relationship == "data_flow"
        for edge in result.edges
    )


def test_builds_typescript_parameter_to_process_edge() -> None:
    mapper = AttackSurfaceMapper()

    result = mapper.scan(
        [
            AttackSurfaceFile(
                filename="command.ts",
                language="typescript",
                code="""
export function runCommand(input: string): void {
  exec(`ping -c 1 ${input}`);
}
""".strip(),
            )
        ]
    )

    source = next(
        node
        for node in result.nodes
        if node.kind == "function_parameter"
        and node.symbol == "input"
    )
    sink = next(
        node
        for node in result.nodes
        if node.kind == "process_execution"
    )

    assert any(
        edge.source == source.id
        and edge.target == sink.id
        and edge.relationship == "data_flow"
        for edge in result.edges
    )


def test_parameter_flow_does_not_cross_functions() -> None:
    mapper = AttackSurfaceMapper()

    result = mapper.scan(
        [
            AttackSurfaceFile(
                filename="separate.py",
                language="python",
                code="""
import os


def receive(command):
    return command.strip()


def execute():
    command = "uptime"
    return os.system(command)
""".strip(),
            )
        ]
    )

    assert not any(
        edge.relationship == "data_flow"
        and any(
            node.id == edge.source
            and node.kind == "function_parameter"
            for node in result.nodes
        )
        for edge in result.edges
    )


def test_collects_multiline_typescript_sink_and_flow() -> None:
    mapper = AttackSurfaceMapper()

    result = mapper.scan(
        [
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
            )
        ]
    )

    source = next(
        node
        for node in result.nodes
        if node.kind == "function_parameter"
        and node.symbol == "filename"
    )

    sink = next(
        node
        for node in result.nodes
        if node.kind == "filesystem"
    )

    assert sink.line_start == 2
    assert sink.line_end == 5
    assert 'path.join("/srv/uploads", filename)' in (
        sink.evidence
    )
    assert '"utf8"' in sink.evidence

    assert any(
        edge.source == source.id
        and edge.target == sink.id
        and edge.relationship == "data_flow"
        for edge in result.edges
    )

    flow = mapper._trace_local_data_flow(
        code="""
export function loadFile(filename: string): string {
  return fs.readFileSync(
    path.join("/srv/uploads", filename),
    "utf8",
  );
}
""".strip(),
        source_expression="filename",
        sink_expression=sink.evidence,
        source_line=source.line_start,
        sink_line=sink.line_start,
    )

    assert flow == [
        "filename",
        'path.join("/srv/uploads", filename)',
        "fs.readFileSync(...)",
    ]


def test_extracts_nested_tainted_filesystem_step() -> None:
    steps = (
        AttackSurfaceMapper
        ._nested_tainted_flow_steps(
            sink_expression="""
return fs.readFileSync(
path.join("/srv/uploads", filename),
"utf8",
);
""".strip(),
            tainted_names=["filename"],
        )
    )

    assert steps == [
        'path.join("/srv/uploads", filename)',
        "fs.readFileSync(...)",
    ]


def test_ignores_unrelated_nested_call() -> None:
    steps = (
        AttackSurfaceMapper
        ._nested_tainted_flow_steps(
            sink_expression="""
return fs.readFileSync(
path.join("/srv/uploads", safe_name),
normalize(filename),
);
""".strip(),
            tainted_names=["filename"],
        )
    )

    assert steps == [
        "normalize(filename)",
        "fs.readFileSync(...)",
    ]


def test_preserves_multiple_parameters_on_same_line() -> None:
    mapper = AttackSurfaceMapper()

    result = mapper.scan(
        [
            AttackSurfaceFile(
                filename="math.py",
                language="python",
                code=(
                    "def add(left: int, right: int) -> int:\n"
                    "    return left + right\n"
                ),
            )
        ]
    )

    parameters = {
        node.symbol
        for node in result.nodes
        if node.kind == "function_parameter"
    }

    assert parameters == {
        "left",
        "right",
    }

    parameter_ids = {
        node.id
        for node in result.nodes
        if node.kind == "function_parameter"
    }

    assert len(parameter_ids) == 2
