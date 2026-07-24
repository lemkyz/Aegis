from functools import lru_cache

from aegis.security.memory_policy import (
    MemoryAwarePolicyEngine,
)
from aegis.security.memory_policy_service import (
    SecurityMemoryPolicyService,
)

from aegis.config.settings import get_settings
from aegis.security.security_memory import (
    SecurityMemoryService,
)
from aegis.security.sqlite_memory import (
    SQLiteProjectMemoryStore,
)


@lru_cache
def get_security_memory_service(
) -> SecurityMemoryService:
    """
    Lazily initialize local project security memory.

    Importing the backend does not create or open the SQLite
    database. Storage is initialized only when this dependency
    is requested for the first time.
    """

    settings = get_settings()

    return SecurityMemoryService(
        store=SQLiteProjectMemoryStore(
            settings.security_memory_database_path
        )
    )


@lru_cache
def get_memory_policy_engine(
) -> MemoryAwarePolicyEngine:
    return MemoryAwarePolicyEngine()


def get_security_memory_policy_service(
) -> SecurityMemoryPolicyService:
    return SecurityMemoryPolicyService(
        memory_service=get_security_memory_service(),
        policy_engine=get_memory_policy_engine(),
    )
