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

(defn sha1 [message-bytes]
  (let [md (java.security.MessageDigest/getInstance "SHA-1")]
    (.update md message-bytes)
    (.digest md)))

;; https://stackoverflow.com/questions/10062967/clojures-equivalent-to-pythons-encodehex-and-decodehex
(defn hexify
  "Convert byte sequence to hex string"
  [coll]
  (let [hex [\0 \1 \2 \3 \4 \5 \6 \7 \8 \9 \a \b \c \d \e \f]]
    (letfn [(hexify-byte [b]
              (let [v (bit-and b 0xFF)]
                [(hex (bit-shift-right v 4)) (hex (bit-and v 0x0F))]))]
      (apply str (mapcat hexify-byte coll)))))

;; https://stackoverflow.com/questions/1270703/how-to-retrieve-compute-an-x509-certificates-thumbprint-in-java/47939494
(defn thumbprint [^java.security.cert.X509Certificate crt]
  (-> crt
      (.getEncoded)
      (sha1)
      (hexify)))

(doseq [url *command-line-args*]
  (doseq [^java.security.cert.X509Certificate crt (get-server-certs url)]
    (println
     {:not-after (.getNotAfter crt)
      :not-before (.getNotBefore crt)
      :subject-name (.getName (.getSubjectX500Principal crt))
      :issuer-name (.getName (.getIssuerX500Principal crt))
      :serial-number (.getSerialNumber crt)
      :thumbprint (thumbprint crt)})
    #_(println crt)))
