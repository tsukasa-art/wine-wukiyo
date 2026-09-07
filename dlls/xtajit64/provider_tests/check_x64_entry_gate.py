#!/usr/bin/env python3
"""Verify that every xtajit64 x64-entry path passes the ntdll resync gate."""

from pathlib import Path
import re
import sys


def function_body(source: str, name: str) -> str:
    pattern = re.compile(
        rf"(?m)^[A-Za-z_][A-Za-z0-9_\s*(),]*\b{re.escape(name)}\s*\([^;]*?\)\s*\{{",
        re.DOTALL,
    )
    match = pattern.search(source)
    if not match:
        raise AssertionError(f"missing function {name}")
    start = source.find("{", match.start())
    depth = 0
    for offset in range(start, len(source)):
        if source[offset] == "{":
            depth += 1
        elif source[offset] == "}":
            depth -= 1
            if not depth:
                return source[start : offset + 1]
    raise AssertionError(f"unterminated function {name}")


def require(body: str, token: str, context: str, count: int = 1) -> None:
    actual = body.count(token)
    if actual != count:
        raise AssertionError(f"{context} has {actual} {token!r} references, expected {count}")


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} CPU_C", file=sys.stderr)
        return 2
    source = Path(sys.argv[1]).read_text(encoding="utf-8")

    run = function_body(source, "run_x64_simulation")
    gate = "__wine_arm64ec_prepare_x64_execution()"
    begin = "XTAJIT64_CALL( begin_simulation"
    require(run, gate, "run_x64_simulation")
    if run.find(gate) > run.find(begin):
        raise AssertionError("run_x64_simulation reaches the provider before the ntdll gate")

    flight_bind = function_body(source, "flight_bind_provider")
    authenticated_gate = ("if (!flight_has_active_recorder( state ) ||\n"
                          "        state->flight_teb_authenticated) return;")
    require(flight_bind, authenticated_gate, "flight_bind_provider")
    require(flight_bind, "XTAJIT64_CALL( flight_bind", "flight_bind_provider")
    authenticated_return = flight_bind.find(authenticated_gate)
    bind_call = flight_bind.find("XTAJIT64_CALL( flight_bind")
    if authenticated_return < 0 or authenticated_return > bind_call:
        raise AssertionError("flight_bind_provider repeats the authenticated Unix bind")

    flight_start = function_body(source, "flight_start_transition")
    require(flight_start, "xtajit64_flight_publish_boundary(",
            "flight_start_transition")
    for field in ("flight_causal_boundary_id", "flight_context_generation",
                  "flight_transition_generation"):
        require(flight_start, f"state->{field} = boundary_id;",
                "flight_start_transition")
    if not (flight_start.find("xtajit64_flight_publish_boundary(") <
            flight_start.find("state->flight_causal_boundary_id = boundary_id;")):
        raise AssertionError("flight_start_transition exposes an unpublished boundary")

    begin = function_body(source, "BeginSimulation")
    require(begin, r'b \"#begin_simulation_on_control_stack\"', "BeginSimulation")
    for token in (
        "ldr x15, [x0, #0x848]",
        "cmp x16, x17",
        "movz x9, #0x6880",
        "cmp x16, x15",
        "str x18, [x0, #0x870]",
        "ldr x9, [x18, #0x1788]",
        "mov w15, #1",
        "stlrb w15, [x9]",
        "mov sp, x16",
    ):
        require(begin, token, "BeginSimulation")
    require(begin, "cmp x15, x9", "BeginSimulation", 2)
    recorder_load = begin.find("ldr x15, [x0, #0x848]")
    x18_capture = begin.find("str x18, [x0, #0x870]")
    ownership_cpu = begin.find("ldr x9, [x18, #0x1788]")
    ownership_store = begin.find("stlrb w15, [x9]")
    stack_switch = begin.find("mov sp, x16")
    c_entry = begin.find(r'b \"#begin_simulation_on_control_stack\"')
    if not (recorder_load < x18_capture < ownership_cpu < ownership_store <
            stack_switch < c_entry):
        raise AssertionError(
            "BeginSimulation must validate layout, acquire simulation, then switch stacks"
        )
    if re.search(r"ldr\s+x\d+,\s*\[x15", begin[:stack_switch]):
        raise AssertionError("BeginSimulation dereferences the recorder header before switching stacks")

    control = function_body(source, "begin_simulation_on_control_stack")
    require(control, "run_x64_simulation( state )",
            "begin_simulation_on_control_stack")
    for token in ("state != get_thread_state()",
                  "state->magic != XTAJIT64_THREAD_STATE_MAGIC",
                  "flight_validate_recorder_layout( state )",
                  "require_control_stack_simulation_ownership(",
                  "discard_unwound_transition_frames"):
        require(control, token, "begin_simulation_on_control_stack")
    if not (control.find("flight_validate_recorder_layout( state )") <
            control.find("flight_start_transition( state )") <
            control.find("require_control_stack_simulation_ownership(") <
            control.find("discard_unwound_transition_frames") <
            control.find("run_x64_simulation( state )")):
        raise AssertionError(
            "control-stack C entry does not fail closed before frame reconciliation"
        )
    ownership = function_body(source, "require_control_stack_simulation_ownership")
    for token in ("*(const volatile BOOLEAN *)&cpu->InSimulation",
                  "XTAJIT64_FLIGHT_EVENT_WATCHDOG_VIOLATION",
                  "XTAJIT64_FLIGHT_REASON_SIMULATION_OWNERSHIP",
                  "flight_dump_if_frozen( state, boundary )",
                  "abort_transition( state, STATUS_INVALID_DEVICE_STATE, boundary )"):
        require(ownership, token, "control-stack ownership watchdog")

    discard = function_body(source, "discard_unwound_transition_frames")
    require(discard, "flight_reconcile_transition_frame(",
            "discard_unwound_transition_frames")
    require(discard, "--state->depth", "discard_unwound_transition_frames")
    if discard.find("flight_reconcile_transition_frame(") > discard.find("--state->depth"):
        raise AssertionError("unwound transition depth changes before its reconcile event")
    transition = function_body(source, "xtajit64_transition_from_native")
    require(transition, "run_x64_simulation( state )",
            "xtajit64_transition_from_native", 3)
    require(transition, "ec_context->AMD64_Context.ContextFlags |=",
            "xtajit64_transition_from_native")
    require(transition, "CONTEXT_AMD64_FULL |",
            "xtajit64_transition_from_native")
    require(transition, "CONTEXT_AMD64_FLOATING_POINT;",
            "xtajit64_transition_from_native")
    require(transition, "require_control_stack_simulation_ownership(",
            "xtajit64_transition_from_native")
    if not (transition.find("flight_start_transition( state )") <
            transition.find("require_control_stack_simulation_ownership(") <
            transition.find("capture_fp_state( &ec_context->AMD64_Context )") <
            transition.find("ec_context->AMD64_Context.ContextFlags |=")):
        raise AssertionError("native capture publishes context flags outside its owning boundary")
    require(run, "mismatched_frame = candidate;", "run_x64_simulation")
    require(run, "XTAJIT64_FLIGHT_REASON_CONTINUATION_PAIR",
            "run_x64_simulation")
    require(run, "continuation_rsp", "run_x64_simulation", 0)
    candidate = run.find("continuation_target_seen = TRUE;")
    mismatch = run.find("mismatched_frame = candidate;")
    exact = run.find("if (params.context.rsp == candidate->guest_rsp)")
    violation = run.find("XTAJIT64_FLIGHT_REASON_CONTINUATION_PAIR")
    mismatch_abort = run.find('"x64 exit-thunk continuation stack mismatch"',
                              violation)
    if not candidate < mismatch < exact < violation < mismatch_abort:
        raise AssertionError("continuation watchdog runs before the complete frame search")
    stack_bounds = function_body(source, "get_x64_stack_bounds")
    disabled_gate = stack_bounds.find("if (!result)")
    disabled_cache = stack_bounds.find("cached_identity_stack_range(", disabled_gate)
    disabled_translate = stack_bounds.find("XTAJIT64_CALL( memory_translate", disabled_cache)
    diagnostic_init = stack_bounds.find("memset( result", disabled_translate)
    unix_translate = stack_bounds.find("XTAJIT64_CALL( memory_translate", diagnostic_init)
    post_translate_teb = stack_bounds.find("teb = NtCurrentTeb();", unix_translate)
    if not (disabled_gate < disabled_cache < disabled_translate < diagnostic_init <
            unix_translate < post_translate_teb):
        raise AssertionError(
            "transition-stack fast validation bypassed its authenticated slow path or "
            "diagnostics missed the post-Unixlib TEB sample"
        )
    require(run, "get_x64_stack_bounds(", "run_x64_simulation")
    require(run, "flight_record_transition_stack_violation(", "run_x64_simulation")
    stack_probe = run.find("get_x64_stack_bounds(")
    stack_record = run.find("flight_record_transition_stack_violation(")
    stack_abort = run.find('"invalid semantic x64 stack"')
    if not stack_probe < stack_record < stack_abort:
        raise AssertionError("transition-stack evidence is not frozen before terminal abort")
    classifier = function_body(source, "flight_record_transition_stack_violation")
    for token in (
        "xtajit64_flight_classify_transition_stack(",
        "xtajit64_flight_record_transition_stack_violation_and_freeze(",
        "violation.frames[index]",
    ):
        require(classifier, token, "flight_record_transition_stack_violation")
    native_capture = function_body(source, "xtajit64_capture_native")
    for token in ("ldr x9, [x17, #0x18]", "mov w10, #1",
                  "stlrb w10, [x17]", "mov x17, x9", "mov sp, x17",
                  r'b \"#xtajit64_transition_from_native\"'):
        require(native_capture, token, "xtajit64_capture_native")
    if not (native_capture.find("ldr x9, [x17, #0x18]") <
            native_capture.find("stlrb w10, [x17]") <
            native_capture.find("mov x17, x9") <
            native_capture.find("mov sp, x17") <
            native_capture.find(r'b \"#xtajit64_transition_from_native\"')):
        raise AssertionError(
            "native capture must validate context, acquire simulation, then switch stacks"
        )
    capture = function_body(source, "capture_transition")
    require(capture, r'b \"#xtajit64_capture_native\"', "capture_transition")
    for token in ("ldr x16, [x17, #0x848]", "str x18, [x17, #0x870]"):
        require(capture, token, "capture_transition")
    if capture.find("ldr x16, [x17, #0x848]") > capture.find("str x18, [x17, #0x870]"):
        raise AssertionError("capture_transition stores x18 before checking recorder enablement")
    for thunk in ("DispatchJump", "RetToEntryThunk", "ExitToX64"):
        require(function_body(source, thunk), r'b \"#capture_transition\"', thunk)

    write_guest = function_body(source, "write_guest_u64")
    require(write_guest, "XTAJIT64_MEMORY_TRANSLATE_REQUIRE_WRITE",
            "write_guest_u64")
    if "XTAJIT64_MEMORY_TRANSLATE_REQUIRE_READ" in write_guest:
        raise AssertionError("write_guest_u64 accepts a read-only guest mapping")

    cache_index = function_body(source, "ec_entry_cache_index")
    for token in ("address >>= 4;",
                  "address *= 0xff51afd7ed558ccdull;",
                  "return address & (XTAJIT64_EC_ENTRY_CACHE_SIZE - 1);"):
        require(cache_index, token, "EC entry cache index")
    require(cache_index, "address ^= address >> 33;", "EC entry cache index", 2)
    ec_resolver = function_body(source, "resolve_ec_entry_thunk")
    require(ec_resolver, "ec_entry_cache_index( guest_target )",
            "resolve_ec_entry_thunk")
    if "(guest_target >> 4) & (XTAJIT64_EC_ENTRY_CACHE_SIZE - 1)" in ec_resolver:
        raise AssertionError("EC entry cache still uses the conflict-prone direct index")

    def model_cache_index(address: int) -> int:
        address >>= 4
        address ^= address >> 33
        address = (address * 0xFF51AFD7ED558CCD) & ((1 << 64) - 1)
        address ^= address >> 33
        return address & 31

    conflict_a, conflict_b = 0x1000, 0x1200
    if ((conflict_a >> 4) & 31) != ((conflict_b >> 4) & 31):
        raise AssertionError("EC cache regression pair no longer models a direct-map conflict")
    if model_cache_index(conflict_a) == model_cache_index(conflict_b):
        raise AssertionError("EC cache hash does not separate the regression pair")

    resolver = function_body(source, "resolve_arm64ec_export")
    require(resolver, "!metadata->RedirectionMetadataCount",
            "resolve_arm64ec_export")

    print("xtajit64 x64-entry resync gate coverage verified")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"x64-entry gate check failed: {error}", file=sys.stderr)
        raise SystemExit(1)
