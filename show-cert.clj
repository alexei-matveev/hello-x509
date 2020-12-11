#!/usr/local/bin/clojure
;; https://stackoverflow.com/questions/54612465/how-to-check-tls-certificate-expiration-date-with-clojure
(ns foo.core
  (:require [clojure.java.io :as io]))

;; Type hints seem to be necessary to avoid "Illegal reflective access
;; by clojure.lang.InjectedInvoker" warnings in recent JDK.
(defn get-server-certs [from]
  (let [url (io/as-url from)
        ^javax.net.ssl.HttpsURLConnection conn (.openConnection url)]
    (with-open [_ (.getInputStream conn)]
      (.getServerCertificates conn))))

(doseq [url *command-line-args*]
  (println
   (.getNotAfter ^java.security.cert.X509Certificate (first (get-server-certs url)))))
