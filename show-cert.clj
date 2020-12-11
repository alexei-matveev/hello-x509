#!/usr/local/bin/clojure
;; https://stackoverflow.com/questions/54612465/how-to-check-tls-certificate-expiration-date-with-clojure
(ns foo.core
  (:require [clojure.java.io :as io]))

(defn get-server-certs [from]
  (let [url (io/as-url from)
        conn (.openConnection url)]
    (with-open [_ (.getInputStream conn)]
      (.getServerCertificates conn))))

(doseq [url *command-line-args*]
  (println
   (.getNotAfter (first (get-server-certs url)))))