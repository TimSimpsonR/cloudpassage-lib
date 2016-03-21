(ns cloudpassage-lib.scans
  "Access to Halo scans."
  (:require
   [cemerick.url :as u]
   [clojure.string :as str]
   [manifold.stream :as ms]
   [aleph.http :as http]
   [manifold.deferred :as md]
   [manifold.stream :as ms]
   [environ.core :refer [env]]
   [cloudpassage-lib.core :as cpc]
   [taoensso.timbre :as timbre :refer [error info spy]]
   [clj-time.core :as t :refer [hours ago]]
   [clj-time.format :as tf]
   [camel-snake-kebab.core :as cskc]
   [camel-snake-kebab.extras :as cske]
   [clojure.java.io :as io]
   [clojure.string :refer [blank?]]))

(def ^:private base-scans-url
  "https://api.cloudpassage.com/v1/scans/")

(def ^:private scans-path
  (partial str "/v1/scans/"))

(def ^:private base-servers-url
  "https://api.cloudpassage.com/v1/servers/")

(defn ^:private maybe-flatten-list
  [maybe-list]
  (if (or (string? maybe-list) (nil? maybe-list))
    maybe-list
    (str/join "," maybe-list)))

(defn ^:private scans-url
  ([opts]
   (scans-url base-scans-url opts))
  ([url opts]
   (let [opts (update opts "modules" maybe-flatten-list)]
     (-> (u/url url)
         (update :query merge opts)
         str))))

(defn ^:private scan-server-url
  "URL for fetching most recent scan results of a server."
  [server-id module]
  (str (u/url "https://api.cloudpassage.com/v1/servers/" server-id module)))

(defn ^:private scans-detail-url
  "Compute the URL for a scan detail."
  ([scan-id]
   (scans-detail-url base-scans-url scan-id))
  ([url scan-id]
   (-> (u/url url)
       (assoc :path (scans-path scan-id))
       str)))

(defn ^:private finding-detail-url
  "Compute the URL for a particular finding in a particular scan."
  ([scan-id finding-id]
   (finding-detail-url base-scans-url scan-id finding-id))
  ([url scan-id finding-id]
   (-> (u/url url)
       (assoc :path (scans-path scan-id "/findings/" finding-id))
       str)))

(defn get-page!
  "Gets a page, and handles auth for you."
  [client-id client-secret url]
  (let [token (cpc/fetch-token! client-id client-secret (:fernet-key env))]
    (cpc/get-single-events-page! token url)))

(defn page-response-ok?
  [response]
  (not= :cloudpassage-lib.core/fetch-error response))

(defn map-stream
  "Maps an input stream to an output stream with some function.

  The function is expected to accept the output stream and return another
  function that is called repeatedly for each bit of input."
  [input f]
  (let [output (ms/stream)]
    (ms/connect-via input (f output) output)
    output))

(defn paginated-list!
  "Returns a stream of resources coming from a paginated list."
  [client-id client-secret initial-url resource-key]
  (let [urls-stream (ms/stream 10)]
    (ms/put! urls-stream initial-url)
    (map-stream
     urls-stream
     (fn [scans-stream]
       (fn [url]
         (md/chain
          (get-page! client-id client-secret url)
          (fn [response]
            (if (page-response-ok? response)
              (let [resource (resource-key response)
                    pagination (:pagination response)
                    next-url (:next pagination)]
                (if (blank? next-url)
                  (do (info "no more urls to fetch")
                      (ms/close! urls-stream))
                  (ms/put! urls-stream next-url))
                (ms/put-all! scans-stream resource))
              (do (error "Error getting scans for url: " url)
                  (ms/close! urls-stream)
                  (Exception. "Error fetching scans."))))))))))

(defn scans!
  "Returns a stream of historical scan results matching opts."
  [client-id client-secret opts]
  (paginated-list! client-id client-secret (scans-url opts) :scans))

(defn list-servers!
  "Returns a stream of servers for the given account."
  [client-id client-secret]
  (paginated-list! client-id client-secret base-servers-url :servers))

(defn scans-with-details!
  "Returns a stream of historical scan results with their details.

  Because of the way the CloudPassage API works, you need to first
  query the scans, and then you need to fetch the details for each
  scan, and then you need to fetch the FIM scan details for the
  details (iff the details are FIM). See CloudPassage API docs for
  more illustration."
  [client-id client-secret scans-stream]
  (map-stream
   scans-stream
   (fn [output]
     (fn [scan]
       (md/chain
        (get-page! client-id client-secret (:url scan))
        (fn [response]
          (ms/put! output (assoc scan :scan (:scan response)))))))))

(defn scan-server
  [client-id client-secret server-id module]
  (let [url (scan-server-url server-id module)]
    (get-page! client-id client-secret url)))

(defn scan-each-server!
  "Given a stream of servers, returns a stream of scan data for each server."
  [client-id client-secret module input]
  (map-stream
   input
   (fn [output]
     (fn [{:keys [id]}]
       (md/chain
        (scan-server client-id client-secret id module)
        (fn [response]
          (if (page-response-ok? response)
            (ms/put! output response)
            (error "Error getting scans for server " id))))))))

(defn ^:private report-for-module!
  "Get recent report data for a certain client, and filter based on module."
  [client-id client-secret module-name]
  ;; The docs say we can use "module" as a query parameter but it does
  ;; not work for FIM or SVM, so we have to filter out those items instead.
  (->> (list-servers! client-id client-secret)
       (scan-each-server! client-id client-secret module-name)
       (ms/map #(cske/transform-keys cskc/->kebab-case-keyword %))
       ms/stream->seq))

(defn fim-report!
  "Get the current (recent) FIM report for a particular client."
  [client-id client-secret]
  (report-for-module! client-id client-secret "fim"))

(defn svm-report!
  "Get the current (recent) SVM report for a particular client."
  [client-id client-secret]
  (report-for-module! client-id client-secret "svm"))

(defn sca-report!
  "Get the current (recent) sca report for a particular client."
  [client-id client-secret]
  (report-for-module! client-id client-secret "sca"))
