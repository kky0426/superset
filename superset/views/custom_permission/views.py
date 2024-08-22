import simplejson as json
from flask import redirect, url_for
from flask import request
from flask_appbuilder.api import expose
from flask_appbuilder.security.decorators import has_access
from flask_appbuilder.security.decorators import permission_name
from sqlalchemy import or_

from superset import db
from superset.errors import SupersetError, SupersetErrorType, ErrorLevel
from superset.exceptions import SupersetErrorException
from superset.migrations.shared.security_converge import Permission, PermissionView, \
    ViewMenu
from superset.models.core import Database
from superset.views.base import BaseSupersetView


class CustomPermissionView(BaseSupersetView):
    route_base = "/custompermission"
    class_permission_name = "List Permissions"

    @expose("/", methods=["GET"])
    @has_access
    @permission_name("menu_access")
    def list(self):
        pvm_list = db.session.query(PermissionView).join(Permission).join(
            ViewMenu).filter(
            or_(Permission.name == "table_deny", Permission.name == "column_deny")
        ).all()

        databases = db.session.query(Database).all()
        return self.render_template("superset/models/custom_permission/list.html",
                                    pvm_list=pvm_list,
                                    databases=databases)

    @expose("/<int:database_id>/schemas", methods=["GET"])
    def get_schemas(self, database_id):
        database = db.session.query(Database).filter_by(id=database_id).one()
        schemas = database.get_all_schema_names()
        return json.dumps([{"name": schema} for schema in schemas])

    @expose("/<int:database_id>/schemas/<schema_name>", methods=["GET"])
    @has_access
    @permission_name("menu_access")
    def get_tables(self, database_id, schema_name):
        database = db.session.query(Database).filter_by(id=database_id).one()
        tables = database.get_all_table_names_in_schema(schema_name)
        return json.dumps([{"name": table[0]} for table in tables])

    @expose("/<int:database_id>/schemas/<schema_name>/<table_name>", methods=["GET"])
    @has_access
    @permission_name("menu_access")
    def get_columns(self, database_id, schema_name, table_name):
        database = db.session.query(Database).filter_by(id=database_id).one()
        columns = database.get_columns(table_name=table_name, schema=schema_name)
        return json.dumps([{"name": column['column_name']} for column in columns])

    @expose("/", methods=["POST"])
    @has_access
    @permission_name("menu_access")
    def create(self):
        permission = request.form.get("permission")
        database_id = request.form.get("database")
        schema_name = request.form.get("schema")
        table_name = request.form.get("table")

        database = db.session.query(Database).filter_by(id=database_id).one()
        if permission == "table_deny":
            view_name = f"{database.perm}.[{schema_name}].[{table_name}]"

        elif permission == "column_deny":
            column_name = request.form.get("column")
            view_name = f"{database.perm}.[{schema_name}].[{table_name}].{column_name}"
        else:
            raise SupersetErrorException(
                SupersetError(
                    message=(
                        "Invalid Parameter"
                    ),
                    error_type=SupersetErrorType.INVALID_TEMPLATE_PARAMS_ERROR,
                    level=ErrorLevel.ERROR,
                )
            )
        self.appbuilder.sm.add_permission_view_menu(permission, view_name)
        return redirect(url_for('CustomPermissionView.list'))
