(ns app.main
  (:gen-class)
  (:require [cljwebauthn.core :as webauthn]
            [buddy.auth.accessrules :refer [restrict IRuleHandlerResponse]]
            [buddy.auth.backends.session :refer [session-backend]]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]
            [buddy.hashers :as hashers]
            [clojure.java.io :as io]
            [compojure.core :refer [defroutes context GET POST]]
            [ring.adapter.jetty :refer [run-jetty]]
            [ring.middleware.session :refer [wrap-session]]
            [ring.middleware.params :refer [wrap-params]]
            [ring.util.response :refer [response redirect]]
            [clojure.data.json :as json])
  (:import (java.util UUID)))

;; This is our application database
;; It will contain the registered users
(def database (atom {}))

;; here we register a user given its email and the webauthn4j authenticator
(defn register-user! [email authenticator]
  (let [user {:id (UUID/randomUUID) :email email :authenticator authenticator}]
    (swap! database assoc email user)))

;; get the user from our fake database using given its email
(defn get-user [email]
  (get @database email))

;; This our site properties
(def site
  {:site-id   "localhost",                  ; the site id (for the client)
   :site-name "There's no place like home", ; the site name (for the client)
   :protocol  "http",                       ; the protocol (for webauthn4j)
   :port      8080,                         ; the port (for webauthn4j)
   :host      "localhost"})                 ; the host (for webauthn4j)

;; this is the GET /webauthn/login?email=... function
(defn do-prepare-register [req]
  (-> req
      (get-in [:params "email"])           ; get ?email=
      (webauthn/prepare-registration site) ; prepare the registration for this site and email
      clojure.data.json/write-str           
      response))                           ; outputs the result as JSON

;; this is the POST /webauthn/login function
(defn do-register [req]
  (let [payload (-> req :body (json/read-str :key-fn keyword))]         ; get payload
    (if-let [user (webauthn/register-user payload site register-user!)] ; register user 
      (ring.util.response/created "/login" (json/write-str user))       ; 201, and redirect to /login
      (ring.util.response/status 500))))                                ; 500, if something goes wrong

;; this is the GET /webauthn/register?email=... function
(defn do-prepare-login [req]
  (let [email (get-in req [:params "email"])]                     ; get the email
    (if-let [resp (webauthn/prepare-login email                   ; prepare for login (create challenge) 
                (fn [email] (:authenticator (get-user email))))]  ; retrieve the authenticator in our database
      (response (json/write-str resp))                            ; 200 and outputs JSON if everything ok
      (ring.util.response/status
        (json/write-str {:message 
             (str "Cannot prepare login for user: " email)}) 500))))  ; 500 in case something goes wrong

;; this is the POST /webauthn/register function
(defn do-login [{session :session :as req}]
  (let [payload (-> req :body (json/read-str :key-fn keyword))]  ; get payload
    (let [email (cljwebauthn.b64/decode (:user-handle payload))  ; decode the 'user-handle' which is the email 
          user (get-user email)                                  ; retrieve the user from database
          auth (:authenticator user)]                            ; and get its authenticator
    (if-let [log (webauthn/login-user payload site             ; try to login the user by verifying the signature etc.
                 (fn [email] auth))]
        (assoc (redirect "/") :session 
            (assoc session :identity 
               (select-keys user [:id :email])))                 ; add the user to our session so that it can be authenticated later on
        (redirect "/login")))))                                  ; redirect to login if the user could not log-in


;; check if a user is authenticated
(defn is-authenticated [{:keys [user]}]
  (not (nil? user)))    ; we just check if we have a 'user' key in our session

;; wrap the user in the request so that the handler can retrieve it if needed
(defn wrap-user [handler]
  (fn [{identity :identity :as req}]
    (handler (assoc req :user (get-user (:email identity))))))

;; log out the user
(defn do-logout [{session :session}]
  (assoc (redirect "/login")               ; redirect to /login
    :session (dissoc session :identity)))  ; but first discard the session


(defroutes admin-routes
    (GET "/" [] (fn [_] (slurp (io/resource "admin.html")))))

(defroutes app-routes
    (context "/admin" []   ; only the /admin is restricted to authenticated users
      (restrict admin-routes {:handler is-authenticated}))
    (GET "/" [] (fn [_] (slurp (io/resource "index.html"))))                ; home page
    (GET "/register" [] (fn [_] (slurp (io/resource "register.html"))))    ; register page 
    (GET "/login" [] (fn [_] (slurp (io/resource "login.html"))))          ; login page
    (GET "/logout" [] do-logout)          ; logout page
    
    (context "/webauthn" []                    ; /webauthn
      (GET "/register" [] do-prepare-register) ; prepare registration endpoint
      (POST "/register" [] do-register)        ; registration endpoint
      (GET "/login" [] do-prepare-login)       ; prepare login endpoint
      (POST "/login" [] do-login)))            ; login endpoint


(def my-app
  (let [backend (session-backend)]     ; enable session management
    (-> #'app-routes
        (wrap-user)                    ; wrap authenticated user if present
        (wrap-authentication backend)  ; buddy authentication
        (wrap-authorization backend)   ; buddy authorization
        (wrap-session)                 ; wrap session
        (wrap-params))))               ; and request params


(defn -main []
    (run-jetty my-app {:port 8080 :host "localhost"}))