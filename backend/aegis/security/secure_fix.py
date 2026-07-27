from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Callable
from uuid import uuid4


class SecureFixTransactionError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SecureFixTransaction:
    transaction_id: str
    target: Path
    original_content: bytes
    before_sha256: str
    after_sha256: str
    file_mode: int


class SecureFixTransactionStore:
    """
    Holds rollback material only in process memory.

    Artifacts contain hashes and an opaque transaction
    identifier, never the original source content.
    """

    def __init__(
        self,
        *,
        id_factory: Callable[[], str]
        | None = None,
    ) -> None:
        self._id_factory = (
            id_factory
            if id_factory is not None
            else lambda: f"fix:{uuid4()}"
        )
        self._transactions: dict[
            str,
            SecureFixTransaction,
        ] = {}
        self._lock = RLock()

    def begin(
        self,
        *,
        target: Path,
        original_content: bytes,
        updated_content: bytes,
        file_mode: int,
    ) -> SecureFixTransaction:
        transaction_id = (
            self._id_factory().strip()
        )

        if not transaction_id:
            raise SecureFixTransactionError(
                "Fix transaction IDs must not be "
                "blank."
            )

        transaction = SecureFixTransaction(
            transaction_id=transaction_id,
            target=target,
            original_content=original_content,
            before_sha256=self.digest(
                original_content
            ),
            after_sha256=self.digest(
                updated_content
            ),
            file_mode=stat.S_IMODE(file_mode),
        )

        with self._lock:
            if (
                transaction_id
                in self._transactions
            ):
                raise SecureFixTransactionError(
                    "A fix transaction with this ID "
                    "already exists."
                )

            self._transactions[
                transaction_id
            ] = transaction

        return transaction

    def discard(
        self,
        transaction_id: str,
    ) -> None:
        with self._lock:
            self._transactions.pop(
                transaction_id,
                None,
            )

    def finalize(
        self,
        transaction_id: str,
        *,
        expected_target: Path,
        expected_after_sha256: str,
    ) -> None:
        transaction = self._require(
            transaction_id
        )
        self._require_identity(
            transaction=transaction,
            expected_target=expected_target,
            expected_after_sha256=(
                expected_after_sha256
            ),
        )
        self._require_current_after(
            transaction
        )

        with self._lock:
            self._transactions.pop(
                transaction_id,
                None,
            )

    def verify_pending(
        self,
        transaction_id: str,
        *,
        expected_target: Path,
        expected_after_sha256: str,
    ) -> None:
        transaction = self._require(
            transaction_id
        )
        self._require_identity(
            transaction=transaction,
            expected_target=expected_target,
            expected_after_sha256=(
                expected_after_sha256
            ),
        )
        self._require_current_after(
            transaction
        )

    def rollback(
        self,
        transaction_id: str,
        *,
        expected_target: Path,
        expected_after_sha256: str,
    ) -> None:
        transaction = self._require(
            transaction_id
        )
        self._require_identity(
            transaction=transaction,
            expected_target=expected_target,
            expected_after_sha256=(
                expected_after_sha256
            ),
        )
        self._require_current_after(
            transaction
        )

        self.atomic_write(
            transaction.target,
            transaction.original_content,
            file_mode=(
                transaction.file_mode
            ),
        )

        restored = transaction.target.read_bytes()

        if self.digest(restored) != (
            transaction.before_sha256
        ):
            raise SecureFixTransactionError(
                "Automatic rollback could not verify "
                "the restored source hash."
            )

        with self._lock:
            self._transactions.pop(
                transaction_id,
                None,
            )

    def contains(
        self,
        transaction_id: str,
    ) -> bool:
        with self._lock:
            return (
                transaction_id
                in self._transactions
            )

    def _require(
        self,
        transaction_id: str,
    ) -> SecureFixTransaction:
        with self._lock:
            try:
                return self._transactions[
                    transaction_id
                ]
            except KeyError as exc:
                raise SecureFixTransactionError(
                    "The secure-fix transaction is "
                    "unavailable or already closed."
                ) from exc

    @staticmethod
    def _require_identity(
        *,
        transaction: SecureFixTransaction,
        expected_target: Path,
        expected_after_sha256: str,
    ) -> None:
        if (
            transaction.target
            != expected_target
            or transaction.after_sha256
            != expected_after_sha256
        ):
            raise SecureFixTransactionError(
                "The secure-fix transaction identity "
                "does not match the applied patch."
            )

    @classmethod
    def _require_current_after(
        cls,
        transaction: SecureFixTransaction,
    ) -> None:
        try:
            current = (
                transaction.target.read_bytes()
            )
        except OSError as exc:
            raise SecureFixTransactionError(
                "The patched target cannot be read "
                "for transaction verification."
            ) from exc

        if cls.digest(current) != (
            transaction.after_sha256
        ):
            raise SecureFixTransactionError(
                "The patched target changed after "
                "Aegis applied the fix; refusing to "
                "overwrite newer user work."
            )

    @staticmethod
    def digest(value: bytes) -> str:
        return hashlib.sha256(
            value
        ).hexdigest()

    @staticmethod
    def atomic_write(
        target: Path,
        content: bytes,
        *,
        file_mode: int,
    ) -> None:
        descriptor = -1
        temporary_name: str | None = None

        try:
            descriptor, temporary_name = (
                tempfile.mkstemp(
                    prefix=".aegis-fix-",
                    dir=target.parent,
                )
            )
            os.fchmod(
                descriptor,
                stat.S_IMODE(file_mode),
            )

            with os.fdopen(
                descriptor,
                "wb",
                closefd=True,
            ) as stream:
                descriptor = -1
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())

            os.replace(
                temporary_name,
                target,
            )
            temporary_name = None

            directory_fd = os.open(
                target.parent,
                os.O_RDONLY,
            )

            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

        finally:
            if descriptor >= 0:
                os.close(descriptor)

            if temporary_name is not None:
                try:
                    os.unlink(temporary_name)
                except FileNotFoundError:
                    pass
