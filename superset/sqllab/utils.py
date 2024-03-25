# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
from __future__ import annotations

from typing import Any

import pyarrow as pa

from superset import db, is_feature_enabled
from superset.common.db_query_status import QueryStatus
from superset.config import MASKING_COLUMN_LIST
from superset.daos.database import DatabaseDAO
from superset.models.sql_lab import Query, TabState
import sqlparse, logging

logger = logging.getLogger()

DATABASE_KEYS = [
    "allow_file_upload",
    "allow_ctas",
    "allow_cvas",
    "allow_dml",
    "allow_run_async",
    "allows_subquery",
    "backend",
    "database_name",
    "expose_in_sqllab",
    "force_ctas_schema",
    "id",
    "disable_data_preview",
]

SqlResults = dict[str, Any]

def apply_display_max_row_configuration_if_require(  # pylint: disable=invalid-name
    sql_results: dict[str, Any], max_rows_in_result: int
) -> dict[str, Any]:
    """
    Given a `sql_results` nested structure, applies a limit to the number of rows

    `sql_results` here is the nested structure coming out of sql_lab.get_sql_results, it
    contains metadata about the query, as well as the data set returned by the query.
    This method limits the number of rows adds a `displayLimitReached: True` flag to the
    metadata.

    :param max_rows_in_result:
    :param sql_results: The results of a sql query from sql_lab.get_sql_results
    :returns: The mutated sql_results structure
    """

    def is_require_to_apply() -> bool:
        return (
            sql_results["status"] == QueryStatus.SUCCESS
            and sql_results["query"]["rows"] > max_rows_in_result
        )

    if is_require_to_apply():
        sql_results["data"] = sql_results["data"][:max_rows_in_result]
        sql_results["displayLimitReached"] = True
    return sql_results


def write_ipc_buffer(table: pa.Table) -> pa.Buffer:
    sink = pa.BufferOutputStream()

    with pa.ipc.new_stream(sink, table.schema) as writer:
        writer.write_table(table)

    return sink.getvalue()


def masking_sql_results(sql_results: SqlResults) -> SqlResults:
    sql = sql_results["query"]["sql"]
    alias_dict = get_origin_column_from_alias(sql)   
    sql_results["data"] = list(map(lambda item: mask_by_column_name(item, alias_dict), sql_results["data"]))
    return sql_results


"""
    return dictionary {"alias" : "origin_column_name"}
"""
def get_origin_column_from_alias(sql: str) -> dict:
    statement = sqlparse.parse(sql)[0]
    columns = []

    # select 절에서 조회할 컬럼들을 분리 
    for token in statement.tokens:
        logger.info(token)
        if isinstance(token, sqlparse.sql.IdentifierList):
            for identifier in token.get_identifiers():
                columns.append(str(identifier))
        elif isinstance(token, sqlparse.sql.Identifier):
            columns.append(str(token))
        elif token.ttype is sqlparse.tokens.Keyword:
            break

    alias_dict = {}
    for column in columns:
        # [name, as, n] 과 같이 분리         
        split_word_list = column.split()
        if len(split_word_list) == 3 and split_word_list[1].lower() == "as":
            alias_dict[split_word_list[2]] = split_word_list[0]
    logger.info(alias_dict)
    return alias_dict

def mask_by_column_name(data: dict[str, Any], alias_dict: dict[str, Any]) -> dict:
    for key,value in data.items():
        if key in MASKING_COLUMN_LIST or (key in alias_dict.keys() and alias_dict[key] in MASKING_COLUMN_LIST):
            data[key] = "*"*len(str(value))
    return data

def bootstrap_sqllab_data(user_id: int | None) -> dict[str, Any]:
    tabs_state: list[Any] = []
    active_tab: Any = None
    databases: dict[int, Any] = {}
    for database in DatabaseDAO.find_all():
        databases[database.id] = {
            k: v for k, v in database.to_json().items() if k in DATABASE_KEYS
        }
        databases[database.id]["backend"] = database.backend
    queries: dict[str, Any] = {}

    # These are unnecessary if sqllab backend persistence is disabled
    if is_feature_enabled("SQLLAB_BACKEND_PERSISTENCE"):
        # send list of tab state ids
        tabs_state = (
            db.session.query(TabState.id, TabState.label)
            .filter_by(user_id=user_id)
            .all()
        )
        tab_state_ids = [str(tab_state[0]) for tab_state in tabs_state]
        # return first active tab, or fallback to another one if no tab is active
        active_tab = (
            db.session.query(TabState)
            .filter_by(user_id=user_id)
            .order_by(TabState.active.desc())
            .first()
        )
        # return all user queries associated with existing SQL editors
        user_queries = (
            db.session.query(Query)
            .filter_by(user_id=user_id)
            .filter(Query.sql_editor_id.in_(tab_state_ids))
            .all()
        )
        queries = {
            query.client_id: dict(query.to_dict().items()) for query in user_queries
        }

    return {
        "tab_state_ids": tabs_state,
        "active_tab": active_tab.to_dict() if active_tab else None,
        "databases": databases,
        "queries": queries,
    }
