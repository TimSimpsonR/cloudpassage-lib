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
   [taoensso.timbre :as timbre :refer [info spy]]
   [clj-time.core :as t :refer [hours ago]]
   [clj-time.format :as tf]
   [clojure.java.io :as io]))

(def ^:private base-scans-url
  "https://api.cloudpassage.com/v1/scans/")

(def ^:private scans-path
  (partial str "/v1/scans/"))

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

(defn scans!
  "Returns a stream of historical scan results matching opts."
  [client-id client-secret opts]
  (let [urls-stream (ms/stream 10) ;; absolutely no science here
        scans-stream (ms/stream 20) ;; nor here
        shovel (fn [url]
                 (md/chain
                  (get-page! client-id client-secret url)
                  ;; TODO: error handling here?
                  (fn [response]
                    (let [{:keys [pagination scans]} response
                          next-url (:next pagination)]
                      (if (or (= "" next-url) (nil? next-url))
                        (do (info "no more urls to fetch")
                            (ms/close! urls-stream)
                            (ms/close! scans-stream))
                        (ms/put! urls-stream next-url))
                      (ms/put-all! scans-stream scans)))))]
    (ms/put! urls-stream (scans-url opts))
    (ms/consume-async shovel urls-stream)
    scans-stream))

(defn scans-with-details!
  "Returns a stream of historical scan results with their details.

  Because of the way the CloudPassage API works, you need to first
  query the scans, and then you need to fetch the details for each
  scan, and then you need to fetch the FIM scan details for the
  details (iff the details are FIM). See CloudPassage API docs for
  more illustration."
  [client-id client-secret scans-stream]
  (let [scans-with-details (ms/stream 10)
        add-details (fn [scan])] ;; TODO: actually add details ;)
    (ms/consume-async add-details scans-stream)
    scans-with-details))

(defn fim-report!
  "Get the current (recent) FIM report for a particular client."
  [client-id client-secret]
  (let [opts {"since" (cpc/->cp-date (-> 3 hours ago))}]
    (->> (scans! client-id client-secret opts)
         ms/stream->seq
         (filter (fn [{:keys [module]}] (= module "fim"))))))
