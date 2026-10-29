from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

from depradar.config import get_settings
from depradar.domain.entities import Base

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)


def run_migrations() -> None:
    if context.is_offline_mode():
        context.configure(
            url=get_settings().database_url,
            target_metadata=Base.metadata,
            literal_binds=True,
            dialect_opts={"paramstyle": "named"},
        )
        with context.begin_transaction():
            context.run_migrations()
        return
    supplied_connection = config.attributes.get("connection")
    if supplied_connection is not None:
        context.configure(
            connection=supplied_connection, target_metadata=Base.metadata, compare_type=True
        )
        with context.begin_transaction():
            context.run_migrations()
        return
    engine = create_engine(get_settings().database_url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


run_migrations()
