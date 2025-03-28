/*Copyright (C) 2019-2022 The Xanado Project https://github.com/cdot/Xanado
  License MIT. See README.md at the root of this distribution for full copyright
  and license information. Author Crawford Currie http://c-dot.co.uk*/
/* eslint-env amd, node */
debugger;
define([
  "fs", "proper-lockfile", "async-lock", "bcrypt",
  "express-session", "session-file-store",
  "passport", "passport-strategy",
  "platform", "common/Utils"
], (
  fs, Lockfile, AsyncLock, BCrypt,
  ExpressSession, SessionFileStore,
  Passport, Strategy,
  Platform, Utils
) => {

  const Fs = fs.promises;
  const dbLock = new AsyncLock();

  function pw_hash(pw) {
    if (typeof pw === "undefined")
      return Promise.resolve(pw);
    else
      return BCrypt.hash(pw, 10);
  }

  function pw_compare(pw, hash) {
    if (typeof pw === "undefined")
      return Promise.resolve(typeof hash === "undefined");
    else
      return BCrypt.compare(pw, hash);
  }

  /**
   * This a Passport strategy, radically cut-down from passport-local.
   * It is required because `passport-local` logins fail on null password,
   * and we specifically want to support this.
   * @extends Passport.Strategy
   */
  class XanadoPass extends Strategy {

    /**
     * @param {function} checkUserPass function used to check name and pass
     * @param {function} checkUserToken function used to check reset token
     */
    constructor(checkUserPass, checkToken) {
      super();
      this.name = "xanado";
      this._checkUserPass = checkUserPass;
      this._checkToken = checkToken;
    }

    /*
     * @param {Request} req incoming login request
     */
    authenticate(req) {
      let promise;
      const user = req.body.login_username;
      if (req.body.login_username)
        promise = this._checkUserPass(
          req.body.login_username, req.body.login_password);
      else
        promise = this._checkToken(req.params.token);
      return promise.then(uo => this.success(uo))
      .catch (e => {
        //console.assert(false, `${user}: ${e.message}`);
        this.fail(e.message);
      });
    }
  }

  /**
   * Manage user login, registration, password reset using Express
   * and Passport. User object will be kept in req, and contains
   * `{ name:, email:, key:, pass: }`
   *
   * This makes no pretence of being secure, it is simply a means to
   * manage simple player login to a game. The following HTTP status
   * codes are used in responses: 200, 401, 403, 500
   *
   * Routes specific to XANADO users are:
   * * {@linkcode UserManager#POST_register|POST /register}
   * * {@linkcode UserManager#POST_login|POST /login}
   * * {@linkcode UserManager#POST_change_password|POST /change-password}
   * * {@linkcode UserManager#POST_reset_password|GET /password-reset/:token}
   * * {@linkcode UserManager#GET_users|GET /users}
   *
   * Routes relevant to all login sessions are:
   * * {@linkcode UserManager#POST_logout|POST /logout}
   * * {@linkcode UserManager#GET_session|GET /session}
   * * {@linkcode UserManager#POST_session_settings|POST /session-settings}
   *
   * Routes relevant to OAuth2 providers are:
   * * {@linkcode UserManager#GET_oauth2_providers|GET /oauth2-providers}
   * * {@linkcode UserManager#GET_oauth2_login|GET /oauth2/login/:provider}
   * * {@linkcode UserManager#GET_oauth2_callback|GET /oauth2/login/:provider}
   */
  class UserManager {

    /**
     * Standard key for the robot user
     * @constant {string}
     */
    static ROBOT_KEY = "babefacebabeface";

    /**
     * Construct, adding relevant routes to the given Express application
     * @param {object} config system configuration object
     * @param {object} config.auth optional authentication options
     * @param {string} config.auth.db_file optional path to json file that
     * stores user information
     * @param {object} config.auth.oauth2 optional OAuth2 providers
     * @param {object} config.mail optional mail configuration for use with
     * @param {Express} app Express application object
     */
    constructor(config, app) {
      this.config = config || {};
      this.pwfile = (config.auth && config.auth.db_file)
            ? config.auth.db_file : 'passwd.json';
      this.db = undefined;

      /* istanbul ignore if */
      if (config.debug_server)
        this._debug = console.debug;
      else
        this._debug = () => {};
      // Passport requires ExpressSession to be configured
      const FileStore = SessionFileStore(ExpressSession);
      app.use(ExpressSession({
        name: "XANADO.sid",
        secret: (config.auth ? config.auth.session_secret : undefined)
        || Utils.genKey(),
        store: new FileStore({
          reapInterval: -1
        }),
        resave: false,
        saveUninitialized: false
      }));

      app.use(Passport.initialize());

      // Same as app.use(passport.authenticate("session"));
      app.use(Passport.session());

      Passport.serializeUser((userObject, done) => {
        // Decide what info from the user object loaded from
        // the DB needs to be shadowed in the session as
        // req.user
        //this._debug("serializeUser", userObject);
        done(null, userObject);
      });

      Passport.deserializeUser((userObject, done) => {
        // Session active, look it up to get user
        //this._debug("deserializeUser",userObject);
        // attach user object as req.user
        done(null, userObject);
      });

      Passport.use(new XanadoPass(
        (user, pass) => this.getUser({ name: user, pass: pass }),
        token => this.getUser({ token: token })));

      // Load and configure oauth2 strategies
      const strategies = [];
      /* istanbul ignore if */
      if (this.config.auth && this.config.auth.oauth2) {
        for (let provider in this.config.auth.oauth2) {
          strategies.push(new Promise(resolve => {
            const cfg = this.config.auth.oauth2[provider];
            // .module is used to override the strategy name
            // needed because passport-google-oauth20 declares
            // strategy "google"
            const module = cfg.module || `passport-${provider}`;
            requirejs([module], strategy => {
              this.setUpOAuth2Strategy(strategy, provider, cfg, app);
              resolve();
            });
          }));
        }
      }
      Promise.all(strategies);

      // See if there is a current session
      app.get(
        "/session",
        (req, res) => this.GET_session(req, res));

      // Post a preference update
      app.post(
        "/session-settings",
        (req, res) => this.POST_session_settings(req, res));

      // Remember where we came from
      app.use((req, res, next) => {
        if (/(^|[?&;])origin=/.test(req.url))
          req.session.origin = decodeURI(
            req.url.replace(/^.*[?&;]origin=([^&;]*).*$/,"$1"));
        //this._debug("Remembering origin", req.session.origin);
        next();
      });

      // Register a new user
      app.post(
        "/register",
        (req, res, next) =>
        this.POST_register(req, res, next));

      app.get(
        "/users",
        (req, res) => this.GET_users(req, res));

      // Log in a user
      app.post(
        "/login",
        Passport.authenticate("xanado", {
          // Assign this property in req
          assignProperty: "userObject"
        }),
        (req, res) => this.POST_login(req, res));

      /* istanbul ignore next */
      app.get(
        "/oauth2-providers",
        (req, res) => this.GET_oauth2_providers(req, res));

      // Log out the current signed-in user
      app.post(
        "/logout",
        (req, res) => this.POST_logout(req, res));

      // Send a password reset email to the user with the given email
      app.post(
        "/reset-password",
        (req, res) => this.POST_reset_password(req, res));

      // Receive a password reset from a link in email
      app.get(
        "/password-reset/:token",
        Passport.authenticate("xanado", {
          assignProperty: "userObject"
        }),
        (req, res) => {
          // error in passport will -> 401
          req.userObject.provider = "xanado";
          // Have to call .login or the cookie doesn't get set
          return this.passportLogin(req, res, req.userObject)
          .then(() => res.redirect("/"));
        });

      // Change the password for the current user
      app.post(
        "/change-password",
        (req, res) => this.POST_change_password(req, res));

      // Login using oauth2 service
      // Note: this route MUST be a GET and MUST come from an href and
      // not an AJAX request, or CORS will foul up.
      app.get(
        "/oauth2/login/:provider",
        (req, res) => this.GET_oauth2_login(req, res));

      // oauth2 redirect target
      app.get(
        "/oauth2/callback/:provider",
        (req, res, next) => {
          const mw = Passport.authenticate(
            req.params.provider, { assignProperty: "userObject" });
          return mw(req, res, next);
        },
        (req, res) => this.GET_oauth2_callback(req, res));
    }

    /**
     * Promisify req.login to complete the login process
     * @param {Request} req
     * @param {Response} req
     * @param {object} uo user object
     * @return {Promise} promise that resolves when the login completes
     * @private
     */
    passportLogin(req, res, uo) {
      this._debug("passportLogin ", uo.name, uo.key);
      return new Promise(resolve => {
        req.login(uo, e => {
          /* istanbul ignore if */
          if (e) throw e;
          this._debug(uo.name, uo.key, "logged in");
          resolve(uo);
        });
      });
    }

    /**
     * Load the user DB
     * @return {Promise} promise that resolves to the DB
     * @private
     */
    getDB() {
      return this.db
      ? Promise.resolve(this.db)

      // In an ideal world, proper-lockfile would wait for a lock
      // to be released - but it doesn't, it just errors. So we have
      // to wrap it in a concurrency lock.
      : dbLock.acquire(
        this.pwfile,
        () => this.db
        ? Promise.resolve(this.db)
        : (Lockfile.lock(this.pwfile)
           .then(release => Fs.readFile(this.pwfile)
                 .then(buffer => release()
                       .then(() => this.db = JSON.parse(buffer))))
           .catch(e => {
             // File is unreadable
             this.db = [];
           })
          ))
      .then(() => this.db);
    }

    /**
     * Write the DB after an update e.g. user added, pw change etc
     * @return {Promise} that resolves when the write completes
     * @private
     */
    writeDB() {
      const s = JSON.stringify(this.db, null, 1);
      return dbLock.acquire(
        this.pwfile,
        () => Fs.access(this.pwfile)
        .then(acc => Lockfile.lock(this.pwfile))
        .then(release => Fs.writeFile(
          this.pwfile, s)
              .then(() => release()))
        .catch(e => Fs.writeFile(this.pwfile, s))); // file does not exist
    }

    /**
     * Promise to get the user object for the described user.
     * You can lookup a user without name if you have email or key.
     * @param {object} desc user descriptor
     * @param {string?} desc.key match the user key. This will take
     * precedence over any other type of matching.
     * @param {string?} desc.user user name - if you give this you also
     * have to either give `password` or `ignorePass`
     * @param {string?} desc.pass user password, requires user, may be undefined
     * but must be present if `user` is given.
     * @param {boolean} desc.ignorePass true will ignore passwords
     * @param {string?} desc.email user email
     * @return {Promise} resolve to user object, or throw
     */
    getUser(desc, ignorePass) {
      return this.getDB()
      .then(db => {
        if (typeof desc.key !== "undefined") {
          const uo = db.find(uo => uo.key === desc.key);
          if (uo)
            return uo;
        }

        for (const uo of db) {
          if (typeof desc.token !== "undefined"
              && uo.token === desc.token) {
            // One-time password change token
            delete uo.token;
            return this.writeDB()
            .then(() => uo);
          }

          if (typeof desc.name !== "undefined"
              && uo.name === desc.name) {

            if (ignorePass)
              return uo;
            if (typeof uo.pass === "undefined") {
              if (desc.pass === uo.pass)
                return uo;
              throw new Error(/*i18n*/"wrong-pass");
            }
            return pw_compare(desc.pass, uo.pass)
            .then(ok => {
              if (ok)
                return uo;
              throw new Error(/*i18n*/"wrong-pass");
            })
            .catch(e => {
              this._debug("getUser", desc,
                          "failed; bad pass", e);
              throw new Error(/*i18n*/"wrong-pass");
            });
          }

          if (typeof desc.email !== "undefined"
              && uo.email === desc.email)
            return uo;
        }
        this._debug("getUser", desc, "failed; no such user in",
                    db.map(uo=>uo.key).join(";"));
        throw new Error(/*i18n*/"player-unknown");
      });
    }

    /* istanbul ignore next */
    /**
     * Configure an OAuth2 Passport strategy
     * @private
     */
    setUpOAuth2Strategy(strategy, provider, cfg, app) {
      assert(cfg.clientID && cfg.clientSecret && cfg.callbackURL,
                      `Misconfiguration ${cfg}`);
      Passport.use(new strategy(
        cfg,
        (accessToken, refreshToken, profile, done) => {
          //this._debug("Logging in", profile.displayName);
          if (profile.emails && profile.emails.length > 0)
            profile.email = profile.emails[0].value;
          assert(profile.id && profile.displayName,
                          `Misconfiguration ${profile}`);
          const key = `${provider}-${profile.id}`;
          this.getUser({ key: key })
          .catch(() => {
            // New user
            return this.addUser({
              name: profile.displayName,
              email: profile.email,
              settings: "",
              provider: provider,
              key: key
            });
          })
          .then(uo => {
            if (!profile.email || uo.email === profile.email)
              return uo;
            uo.email = profile.email;
            assert(uo.provider,
                            "Provider expected in user object");
            return this.writeDB();
          })
          .then(uo => done(null, uo));
          // uo will end up in userObject
        }));
    }

    /* istanbul ignore next */
    /**
     * Get a list of oauth2 providers.
     * @param {Request} req
     * @param {Response} res Responds body will be a list of oauth2
     * provider objects, each with the provider name and the logo URL
     * @private
     */
    GET_oauth2_providers(req, res) {
      const list = [];
      if (this.config.auth && this.config.auth.oauth2) {
        for (let name in this.config.auth.oauth2) {
          const cfg = this.config.auth.oauth2[name];
          list.push({ name: name, logo: cfg.logo });
        }
      }
      this.sendResult(res, 200, list);
    }

    /* istanbul ignore next */
    /**
     * Log in to an oauth2 provider.
     * @param {Request} req
     * @param {string} req.provider the provider name
     * @param {Response} res
     * @private
     */
    GET_oauth2_login(req, res) {
      return Passport.authenticate(req.params.provider)(req, res);
    }

    /* istanbul ignore next */
    /**
     * Callback used by an OAuth2 provider.
     * @param {Request} req
     * @param {string} req.provider the provider name
     * @param {Response} res
     * @private
     */
    GET_oauth2_callback(req, res) {
      // error will -> 401
      //this._debug("OAuth2 user is", Utils.stringify(req.userObject));
      return req.login(req.userObject, () => {
        // Back to where we came from
        //this._debug("Redirect to",req.session.origin);
        res.redirect(req.session.origin);
      });
    }

    /**
     * Make a one-time token for use in password resets
     * @param {Object} user user object
     * @private
     */
    setToken(user) {
      const token = Math.floor(1e16 + Math.random() * 9e15)
            .toString(36).substr(0, 10);
      user.token = token;
      return this.writeDB()
      .then(() => token);
    }

    /**
     * Add a new user to the DB, if they are not already there
     * @param {object} desc user descriptor
     * @param {string} desc.user user name
     * @param {string} desc.provider authentication provider e.g. google
     * @param {string?} desc.pass user password, requires user.
     * Will be encrypted if defined before saving.
     * @param {string?} desc.email user email
     * @param {string?} key optionally force the key to this
     * @return {Promise} resolve to user object, or reject if duplicate
     */
    addUser(desc) {
      return this.getDB()
      .then(() => {
        if (!desc.key)
          desc.key = Utils.genKey(this.db.map(f => f.key));
        return pw_hash(desc.pass);
      })
      .then(pw => {
        if (typeof pw !== "undefined")
          desc.pass = pw;
        this._debug("Add user", desc);
        this.db.push(desc);
        return this.writeDB()
        .then(() => desc);
      });
    }

    /**
     * Send a result to the browser
     * @private
     */
    sendResult(res, status, info) {
      this._debug(`<-- ${status}`, info);
      res.status(status).send(info);
    }

    /**
     * Handle registration of a user using Xanado password database
     * @param {Request} req The body of the
     * request must contain `register_username` and may contain
     * `register_email` and `register_password`.
     * @param {Response} res
     * @private
     */
    POST_register(req, res, next) {
      const username = req.body.register_username;
      const email = req.body.register_email;
      const pass = req.body.register_password;
      if (!username)
        return this.sendResult(
          res, 403, [ /*i18n*/"bad-user", username ]);
      return this.getUser({name: username }, true)
      .then(() => {
        this.sendResult(
          res, 403, [ /*i18n*/"already-registered", username ]);
      })
      .catch(() => {
        // New user
        return this.addUser({
          name: username,
          email: email,
          provider: "xanado",
          pass: pass
        })
        .then(userObject => this.passportLogin(req, res, userObject))
        .then(() => this.GET_session(req, res));
      });
    }

    /**
     * Simply forgets the currently logged-in user, doesn't log OAuth2
     * users out from the provider.
     * @param {Request} req
     * @param {Response} res
     * @private
     */
    POST_logout(req, res) {
      if (req.isAuthenticated()) {
        const departed = req.session.passport.user.name;
        this._debug("Logging out", departed);
        return new Promise(resolve => req.logout(resolve))
        .then(() => this.sendResult(res, 200, [
          /*i18n*/"signed-out", departed ]));
      }
      return this.sendResult(
        res, 401, [ /*i18n*/"Not signed in" ]);
    }

    /**
     * Gets a list of known users
     * @param {Request} req request
     * @param {Response} res Sends a list of users. Only the user name and
     * key are sent.
     * @private
     */
    GET_users(req, res) {
      if (req.isAuthenticated())
        return this.getDB()
      .then(db => this.sendResult(
        res, 200,
         db.map(uo => {
          return { name: uo.name, key: uo.key  };
        })));

      return this.sendResult(
        res, 401, [ /*i18n*/"Not signed in" ]);
    }

    /**
     * Handle XANADO login.
     * @param {Request} req The body of the request
     * must contain `login_username` and `login_password`
     * fields. BasicAuth is NOT supported.
     * @param {Response} res response
     * @private
     */
    POST_login(req, res) {
      // error in passport will -> 401
      req.userObject.provider = "xanado";
      // Have to call .login or the cookie doesn't get set
      return this.passportLogin(req, res, req.userObject)
      .then(() => this.sendResult(res, 200, []));
    }

    /**
     * Change the current users' password.
     * @param {Request} req The request body must contain `password`,
     * the new password
     * @param {Response} res
     * @private
     */
    POST_change_password(req, res) {
      if (req.session
          && req.session.passport
          && req.session.passport.user) {
        const pass = req.body.password;
        const userObject = req.session.passport.user;
        this._debug("Changing pw for", userObject.name, userObject.key);
        return pw_hash(pass)
        .then(pass => userObject.pass = pass)
        .then(() => this.getUser(userObject))
        .then(uo => {
          uo.pass = userObject.pass;
        })
        .then(() => this.writeDB())
        .then(() => this.sendResult(res, 200, [
          /*i18n*/"pass-changed",
          req.session.passport.user.name ]));
      }
      return this.sendResult(
        res, 401, [ /*i18n*/"Not signed in" ]);
    }

    /**
     * Reset the password for the given email address. A reset token will
     * be mailed to the user that they can then use to log in.
     * @param {Request} req The request body must contain `reset_email`
     * @param {Response} res
     * @private
     */
    POST_reset_password(req, res) {
      assert(this.config.mail && this.config.mail.transport,
                      "Mail is not configured");
      const email = req.body.reset_email;
      this._debug("/reset-password for", email);
      const surly = `${req.protocol}://${req.get("Host")}`;
      return this.getUser({email: email})
      .then(user => {
        return this.setToken(user)
        .then(token => {
          const url = `${surly}/password-reset/${token}`;
          this._debug(`Send password reset ${url} to ${user.email}`);
          return this.config.mail.transport.sendMail({
            from: this.config.mail.sender,
            to:  user.email,
            subject: Platform.i18n("Password reset"),
            text: Platform.i18n(
              "email-reset-plain", url),
            html: Platform.i18n(
              "email-reset-body", url)
          })
          .then(() => this.sendResult(
            res, 200, [ /*i18n*/"text-reset-sent", user.name ]))
          .catch(
            /* istanbul ignore next */
            e => {
              console.error("WARNING: Mail misconfiguration?", e);
              return this.sendResult(
                res, 500, [  /*i18n*/"text-no-email" ]);
            });
        });
      })
      .catch(e => this.sendResult(res, 403, [ e.message, email ]));
    }

    /**
     * Report who is logged in. This will return a redacted user
     * object, with just the user name and uniqe key.
     * @param {Request} req
     * @param {Response} res Response body will contain a redacted user
     * object, with
     * * name: the player name
     * * key: the player unique key
     * * provider: the login provider
     * * settings: the cached user settings for the user
     * @private
     */
    GET_session(req, res) {
      if (req.user)
        // Return redacted user object
        return this.sendResult(res, 200, {
          name: req.user.name,
          provider: req.user.provider,
          key: req.user.key,
          settings: req.user.settings
        });
      return this.sendResult(res, 401, [  /*i18n*/"Not signed in" ]);
    }

    /**
     * Write new session settings for the user
     * @param {Request} req
     * @param {Response} res
     * @private
     */
    POST_session_settings(req, res) {
      if (req.user) {
        req.user.settings = req.body;
        return this.getUser(req.user)
        .then(user => {
          user.settings = req.body;
          this._debug("Session settings", user);
          return this.writeDB()
          .then(() => this.sendResult(res, 200, req.user.settings));
        });
      }
      /* istanbul ignore next */
      return this.sendResult(res, 401, [  /*i18n*/"Not signed in" ]);
    }

    /**
     * Middleware to check if a user is signed in. Use it with
     * @param {Request} req
     * @param {Response} res
     * @param {function} next skip to next route
     * any route where a logged-in user is required.
     */
    checkLoggedIn(req, res, next) {
      if (req.isAuthenticated())
        return next();
      return this.sendResult(res, 401, [ /*i18n*/"Not signed in" ]);
    }
  }

  return UserManager;
});
