import flask_appbuilder.security.views as default
from flask_appbuilder.baseviews import expose
from flask_appbuilder.security.decorators import has_access
import logging
from superset.extensions import event_logger
from superset.utils.log import DBEventLogger

logger = logging.getLogger(__name__)
event_logger = DBEventLogger()

class PermissionModelView(default.PermissionModelView):


    @expose("/edit/<pk>", methods=["GET", "POST"])
    @has_access
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.edit",
        log_to_statsd=True,
    )
    def edit(self, pk):
        event_logger.log_this
        return super().edit(pk)
    
    @expose("/list/")
    @has_access
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.list",
        log_to_statsd=True,
    )
    def list(self):
        event_logger.log_this
        return super().list()
    
    @expose("/add", methods=["GET", "POST"])
    @has_access
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.add",
        log_to_statsd=True,
    )
    def add(self):
        return super().add()
        
    @expose("/delete/<pk>", methods=["GET", "POST"])
    @has_access
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.delete",
        log_to_statsd=True,
    )
    def delete(self, pk):
        return super().delete(pk)

class PermissionViewModelView(default.PermissionViewModelView):

    @expose("/edit/<pk>", methods=["GET", "POST"])
    @has_access
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.edit",
        log_to_statsd=True,
    )
    def edit(self, pk):
        return super().edit(pk)
    
    @expose("/list/")
    @has_access
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.list",
        log_to_statsd=True,
    )
    def list(self):
        return super().list()
    
    @expose("/add", methods=["GET", "POST"])
    @has_access
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.add",
        log_to_statsd=True,
    )
    def add(self):
        return super().add()
        
    @expose("/delete/<pk>", methods=["GET", "POST"])
    @has_access
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.delete",
        log_to_statsd=True,
    )
    def delete(self, pk):
        return super().delete(pk)
        


class RoleModelView(default.RoleModelView):

    @expose("/edit/<pk>", methods=["GET", "POST"])
    @has_access
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.edit",
        log_to_statsd=True,
    )
    def edit(self, pk):
        event_logger.log_context(action="edit role")
        return super().edit(pk)


    @expose("/list/")
    @has_access
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.list",
        log_to_statsd=True,
    )
    def list(self):
        event_logger.log_context(action="list role")
        return super().list()
      
    
    @expose("/add", methods=["GET", "POST"])
    @has_access
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.add",
        log_to_statsd=True,
    )
    def add(self):
        event_logger.log_context("add role")
        return super().add()
    
    @expose("/delete/<pk>", methods=["GET", "POST"])
    @has_access
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.delete",
        log_to_statsd=True,
    )
    def delete(self, pk):
        return super().delete(pk)
    
class ViewMenuModelView(default.ViewMenuModelView):

    @expose("/edit/<pk>", methods=["GET", "POST"])
    @has_access
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.edit",
        log_to_statsd=True,
    )
    def edit(self, pk):
        return super().edit(pk)


    @expose("/list/")
    @has_access
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.list",
        log_to_statsd=True,
    )
    def list(self):
        return super().list()
    
    @expose("/add", methods=["GET", "POST"])
    @has_access
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.add",
        log_to_statsd=True,
    )
    def add(self):
        return super().add()
        
    @expose("/delete/<pk>", methods=["GET", "POST"])
    @has_access
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.delete",
        log_to_statsd=True,
    )
    def delete(self, pk):
        return super().delete(pk)
    
class UserModelView(default.UserModelView):

    @expose("/edit/<pk>", methods=["GET", "POST"])
    @has_access
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.edit",
        log_to_statsd=True,
    )
    def edit(self, pk):
        return super().edit(pk)
    
    @expose("/list/")
    @has_access
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.list",
        log_to_statsd=True,
    )
    def list(self):
        event_logger.log_this
        return super().list()
    
    @expose("/add", methods=["GET", "POST"])
    @has_access
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.add",
        log_to_statsd=True,
    )
    def add(self):
        event_logger.log_this
        return super().add()
        
    @expose("/delete/<pk>", methods=["GET", "POST"])
    @has_access
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.delete",
        log_to_statsd=True,
    )
    def delete(self, pk):
        event_logger.log_this
        return super().delete(pk)
    
class UserDBModelView(UserModelView):
    pass

class UserOAuthModelView(UserModelView):
    pass

