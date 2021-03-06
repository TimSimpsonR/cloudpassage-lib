(ns cloudpassage-lib.scans-test
  (:require
   [cloudpassage-lib.scans :as scans]
   [cloudpassage-lib.core :refer [cp-date-formatter]]
   [clj-time.format :as tf]
   [clj-time.core :as t :refer [millis hours ago within?]]
   [clojure.test :refer [deftest testing is are]]
   [manifold.stream :as ms]
   [manifold.deferred :as md]
   [cemerick.url :as u]
   [taoensso.timbre :as timbre :refer [info spy]]))

(deftest scans-url-tests
  (are [opts expected] (= expected (#'scans/scans-url opts))
    {"modules" "fim"}
    "https://api.cloudpassage.com/v1/scans?modules=fim"

    {"modules" "fee,fie,foe,fim"}
    "https://api.cloudpassage.com/v1/scans?modules=fee%2Cfie%2Cfoe%2Cfim"

    {"modules" ["fee" "fie" "foe" "fim"]}
    "https://api.cloudpassage.com/v1/scans?modules=fee%2Cfie%2Cfoe%2Cfim")
  (testing "with specified base URL"
    (are [url opts expected-query] (= expected-query
                                      (-> (#'scans/scans-url url opts)
                                          u/url
                                          :query))
      "https://api.cloudpassage.com/v1/scans?since=2016-01-01"
      {"modules" "fim"}
      {"modules" "fim"
       "since" "2016-01-01"})))

(deftest scans-detail-url-tests
  (is (= "https://api.cloudpassage.com/v1/scans/abcdef"
         (#'scans/scans-detail-url "abcdef")))
  (is (= "https://abc.com/v1/scans/abcdef"
         (#'scans/scans-detail-url "https://abc.com/" "abcdef"))))

(deftest finding-detail-url-tests
  (is (= "https://api.cloudpassage.com/v1/scans/abcdef/findings/xyzzy"
         (#'scans/finding-detail-url "abcdef" "xyzzy")))
  (is (= "https://abc.com/v1/scans/abcdef/findings/xyzzy"
         (#'scans/finding-detail-url "https://abc.com/" "abcdef" "xyzzy"))))

(defn ^:private index->module
  "Given an index of a (fake, test-only) scan, return a module for that scan."
  [i]
  (case (mod i 3)
    0 "fim"    ;; file integrity management
    1 "svm"    ;; software version management
    2 "ccm"))  ;; configuration change management

(def fake-pages 10)
(def scans-per-page 10)

(defn ^:private fake-get-page!
  [client-id client-secret url]
  (is (= client-id "lvh"))
  (is (= client-secret "hunter2"))
  (let [parsed-url (u/url url)
        query (:query parsed-url)
        page-num (-> query
                     (get "next" "0")
                     Integer/parseInt)
        next-page (if (< page-num fake-pages)
                    (str (assoc-in parsed-url [:query "next"] (inc page-num)))
                    "")]
    (when-some [since (query "since")]
      (let [since (tf/parse cp-date-formatter since)
            fudged (t/interval (-> 4 hours ago) (-> 3 hours ago))]
        (is (within? fudged since))))
    {:scans (for [index-in-page (range scans-per-page)
                  :let [scan-index (+ (* scans-per-page page-num)
                                      index-in-page)]]
              {:scan-id scan-index
               :module (index->module scan-index)})
     :pagination {:next next-page}}))

(deftest scans!-tests
  (with-redefs [scans/get-page! fake-get-page!]
    (let [scans-stream (scans/scans! "lvh" "hunter2" {"modules" "fim"})
          scans (ms/stream->seq scans-stream)]
      (is (= (for [scan-id (range (* fake-pages scans-per-page))]
               {:scan-id scan-id
                :module (index->module scan-id)})
             scans))
      (is (ms/closed? scans-stream)))))

(deftest fim-report!-tests
  (with-redefs [scans/get-page! fake-get-page!]
    (let [report (scans/fim-report! "lvh" "hunter2")]
      (is (= (for [scan-id (range (* fake-pages scans-per-page))
                   :let [module (index->module scan-id)]
                   :when (= module "fim")]
               {:scan-id scan-id
                :module module})
             report)))))
