import flask_appbuilder.security.views as default
from flask_appbuilder.baseviews import expose
from flask_appbuilder.security.decorators import has_access
import logging
from superset.extensions import event_logger
from superset.utils.log import DBEventLogger

import logging
import re
from typing import Any, List, Optional
import jwt
from flask_appbuilder._compat import as_unicode
from werkzeug.wrappers import Response as WerkzeugResponse
from flask_appbuilder.utils.base import get_safe_redirect
from flask_login import login_user

#from flask import abort, current_app, flash, g, redirect, request, session, url_for
from flask import flash, g, redirect, request, session, url_for

###
from flask_appbuilder.security.forms import (
    LoginForm_db,
)
from flask import current_app
from flask_login import user_logged_out
###
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


## okta 로그인 시 
class AuthOAuthView(default.AuthOAuthView):

    @expose("/oauth-authorized/<provider>")
    def oauth_authorized(self, provider: str) -> WerkzeugResponse:
        logger.debug("Authorized init")
        if provider not in self.appbuilder.sm.oauth_remotes:
            flash("Provider not supported.", "warning")
            logger.warning("OAuth authorized got an unknown provider %s", provider)
            return redirect(self.appbuilder.get_url_for_login)
        try:
            resp = self.appbuilder.sm.oauth_remotes[provider].authorize_access_token()
        except Exception as e:
            logger.error("Error authorizing OAuth access token: %s", e)
            flash("The request to sign in was denied.", "error")
            return redirect(self.appbuilder.get_url_for_login)
        if resp is None:
            flash("You denied the request to sign in.", "warning")
            return redirect(self.appbuilder.get_url_for_login)
        logger.debug("OAUTH Authorized resp: %s", resp)
        # Retrieves specific user info from the provider
        try:
            self.appbuilder.sm.set_oauth_session(provider, resp)
            userinfo = self.appbuilder.sm.oauth_user_info(provider, resp)
        except Exception as e:
            logger.error("Error returning OAuth user info: %s", e)
            user = None
        else:
            logger.debug("User info retrieved from %s: %s", provider, userinfo)
            # User email is not whitelisted
            if provider in self.appbuilder.sm.oauth_whitelists:
                whitelist = self.appbuilder.sm.oauth_whitelists[provider]
                allow = False
                for email in whitelist:
                    if "email" in userinfo and re.search(email, userinfo["email"]):
                        allow = True
                        break
                if not allow:
                    flash("You are not authorized.", "warning")
                    return redirect(self.appbuilder.get_url_for_login)
            else:
                logger.debug("No whitelist for OAuth provider")
            user = self.appbuilder.sm.auth_user_oauth(userinfo)

        if user is None:
            flash(as_unicode(self.invalid_login_message), "warning")
            return redirect(self.appbuilder.get_url_for_login)
        else:
            try:
                state = jwt.decode(
                    request.args["state"], session["oauth_state"], algorithms=["HS256"]
                )
            except (jwt.InvalidTokenError, KeyError):
                flash(as_unicode("Invalid state signature"), "warning")
                return redirect(self.appbuilder.get_url_for_login)
            
            redis = current_app.config["SESSION_REDIS"]

            # redis 에서 해당 username으로 된 이전 session id 찾기
            before_sid = redis.get(user.username) if user is not None else None

            ## 이전 session id가 남아있으면 세션 만료
            if before_sid is not None:
                before_session_key = "session:" + before_sid.decode("utf-8")
                redis.delete(before_session_key)
                logger.info("delete before session key : %s",before_session_key)
           
            login_user(user, remember=False)
            
            # login 후 redis에 session id 저장 
            redis.set(user.username, session.sid)

            if before_sid is not None and before_sid != session.sid:
                flash("새로운 세션에서 로그인 하셨습니다. 이미 접속중인 세션을 해제합니다.")
                
            next_url = self.appbuilder.get_url_for_index
            # Check if there is a next url on state
            if "next" in state and len(state["next"]) > 0:
                next_url = get_safe_redirect(state["next"][0])
            return redirect(next_url)
        

## id/pw로 로그인 시 
class AuthDBView(default.AuthDBView):

    login_template = "appbuilder/general/security/login_db.html"
    COOKIE_NAME = "remember_token"

    @expose("/login/", methods=["GET", "POST"])
    def login(self):
        logger.info("secetkey:%s",current_app.secret_key)
        if g.user is not None and g.user.is_authenticated:
            return redirect(self.appbuilder.get_url_for_index)
        form = LoginForm_db()
        if form.validate_on_submit():
            next_url = get_safe_redirect(request.args.get("next", ""))
            user = self.appbuilder.sm.auth_user_db(
                form.username.data, form.password.data
            )
            
            if user is None:
                return redirect(self.appbuilder.get_url_for_index)
            
            redis = current_app.config["SESSION_REDIS"]

            # redis에서 해당 username으로 된 이전 session id 찾기
            before_sid = redis.get(user.username) if user is not None else None

            ## 이전 session id가 남아있으면 세션 만료
            if before_sid is not None:
                before_session_key = "session:" + before_sid.decode("utf-8")
                redis.delete(before_session_key)
           
            login_user(user, remember=False)
            
            # login 후 redis에 session id 저장 
            redis.set(user.username, session.sid)
            logger.info("before:%s",before_sid)
            logger.info("current:%s",session.sid)

            if before_sid is not None and before_sid != session.sid:
                flash("새로운 세션에서 로그인 하셨습니다. 이미 접속중인 세션을 해제합니다.")
            return redirect(self.appbuilder.get_url_for_index)
        return self.render_template(
            self.login_template, title=self.title, form=form, appbuilder=self.appbuilder
        )
            
