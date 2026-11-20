"""Pytest harness simulating the GenVM runtime for UptimeShield unit & property tests.

Controls:
  gl.clock              deterministic transaction timestamp in unix seconds (advance())
  gl.page               default HTML/text returned by gl.nondet.web.render
  gl.pages              per-URL override map (string payload or Exception)
  gl.llm_reply          mocked JSON response from gl.nondet.exec_prompt
  gl.comparative_fails  when True, eq_principle.prompt_comparative raises an error
  gl.prompts            recorded prompts sent during execution
  gl.balance            simulated contract balance in wei
  gl.transfers          list of (recipient, amount) emitted via external transfers
"""

from __future__ import annotations

import sys
import types
from pathlib import Path


SAMPLE_DOC_1 = "Month 1 status: indexer v0.1.0 deployed on 5 January with zero downtime."
SAMPLE_DOC_2 = "Month 2 status: public gateway v0.2.0 deployed on 3 February with zero downtime."
SAMPLE_DOC_3 = "Month 3 status: documentation portal v1.0.0 launched on 2 March."


def _install_fake_genlayer() -> None:
    existing = sys.modules.get("genlayer")
    if existing is not None and getattr(existing, "_fake_genvm", False):
        return

    gl = types.ModuleType("genlayer")
    gl._fake_genvm = True

    class _Write:
        """Decorator supporting `@gl.public.write` and `@gl.public.write.payable`."""

        def __call__(self, fn):
            fn._payable = False
            return fn

        @staticmethod
        def payable(fn):
            fn._payable = True
            return fn

    class _Public:
        write = _Write()

        @staticmethod
        def view(fn):
            return fn

    class TreeMap(dict):
        def __class_getitem__(cls, item):
            return cls

    class DynArray(list):
        def __class_getitem__(cls, item):
            return cls

    class _Contract:
        def __new__(cls, *args, **kwargs):
            obj = super().__new__(cls)
            for name, kind in getattr(cls, "__annotations__", {}).items():
                label = kind if isinstance(kind, str) else getattr(kind, "__name__", "")
                if label.startswith("TreeMap"):
                    setattr(obj, name, TreeMap())
                elif label.startswith("DynArray"):
                    setattr(obj, name, DynArray())
            return obj

        @property
        def balance(self):
            return gl.balance

    class _WalletProxy:
        def __init__(self, address):
            self.address = str(address)

        def emit_transfer(self, value=0, **kwargs):
            if kwargs:
                raise TypeError("external transfers take no `on` argument")
            amount = int(value)
            if amount <= 0 or amount > gl.balance:
                raise Exception("transfer exceeds the contract balance")
            gl.balance -= amount
            gl.transfers.append((self.address, amount))

    def _evm_interface(cls):
        return _WalletProxy

    class _EqPrinciple:
        @staticmethod
        def prompt_comparative(leader_fn, principle="", /):
            if getattr(gl, "comparative_fails", False):
                raise Exception("comparative consensus unavailable")
            return leader_fn()

        @staticmethod
        def strict_eq(leader_fn):
            return leader_fn()

    def _render(url, mode="text"):
        page = gl.pages.get(url, gl.page)
        if isinstance(page, Exception):
            raise page
        return page

    def _exec_prompt(prompt, response_format=None):
        gl.prompts.append(prompt)
        reply = gl.llm_reply
        if isinstance(reply, Exception):
            raise reply
        return reply

    class UserError(Exception):
        def __init__(self, message=""):
            super().__init__(message)
            self.message = message

    gl.contract = types.SimpleNamespace(Contract=_Contract)
    gl.Contract = _Contract
    gl.vm = types.SimpleNamespace(UserError=UserError)
    gl.gl = gl
    gl.Address = str
    gl.public = _Public()
    gl.evm = types.SimpleNamespace(contract_interface=_evm_interface)
    gl.message = types.SimpleNamespace(
        sender_address="0x1111111111111111111111111111111111111111", value=0
    )
    gl_types = types.ModuleType("genlayer.types")
    gl_types.Address = str
    gl.types = gl_types
    sys.modules["genlayer.types"] = gl_types
    gl_storage = types.ModuleType("genlayer.storage")
    gl_storage.TreeMap = TreeMap
    gl_storage.DynArray = DynArray
    gl.storage = gl_storage
    sys.modules["genlayer.storage"] = gl_storage
    gl.eq_principle = _EqPrinciple()
    gl.nondet = types.SimpleNamespace(
        web=types.SimpleNamespace(render=_render),
        exec_prompt=_exec_prompt,
    )

    gl.clock = 1_767_225_600  # 2026-01-01T00:00:00Z
    gl.page = SAMPLE_DOC_1
    gl.llm_reply = '{"finding": "incident"}'
    gl.comparative_fails = False
    gl.prompts = []
    gl.balance = 0
    gl.pages = {}
    gl.transfers = []
    sys.modules["genlayer"] = gl


def load_contract(repo_root: Path, filename: str = "UptimeShield.py"):
    _install_fake_genlayer()
    gl = sys.modules["genlayer"]
    path = repo_root / "contracts" / filename
    mod_name = f"contract_{filename.replace('.', '_')}"
    module = types.ModuleType(mod_name)
    module.__dict__["gl"] = gl
    exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), module.__dict__)

    real_datetime = module.__dict__["datetime"]

    class _TxDatetime(real_datetime):  # type: ignore[misc, valid-type]
        @classmethod
        def now(cls, tz=None):
            return real_datetime.fromtimestamp(gl.clock, tz)

    module.__dict__["datetime"] = _TxDatetime
    sys.modules[mod_name] = module
    return module


def advance(gl, seconds: int) -> None:
    gl.clock += int(seconds)


def reset(gl) -> None:
    gl.clock = 1_767_225_600
    gl.page = SAMPLE_DOC_1
    gl.llm_reply = '{"finding": "incident"}'
    gl.comparative_fails = False
    gl.prompts = []
    gl.balance = 0
    gl.pages = {}
    gl.transfers = []
    gl.message.value = 0
    gl.message.sender_address = "0x1111111111111111111111111111111111111111"


def pay(gl, method, value: int, *args):
    if value and not getattr(method, "_payable", False):
        raise Exception("method is not payable")
    gl.message.value = int(value)
    gl.balance += int(value)
    try:
        return method(*args)
    finally:
        gl.message.value = 0
