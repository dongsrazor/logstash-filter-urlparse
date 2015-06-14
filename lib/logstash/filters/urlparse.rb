# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "uri"

class LogStash::Filters::Urlparse < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   example {
  #     request_headers => [captured_request_headers]
  #     http_request => [http_request]
  #   }
  # }
  #
  config_name "urlparse"
  
  # Replace the message with this value.
  config :request_headers, :validate => :string, :default => "captured_request_headers"
  config :http_request, :validate => :string, :default => "http_request"

  public
  def register
    # Add instance variables 
  end # def register

  public
  def filter(event)

    if @request_headers
      host, referer = event[@request_headers].split("|")
      event["host"] = host
      event["referer"] = referer
    end

    if @http_request
      u = URI(event[@http_request])
      event["path"] = u.path
      event["query"] = u.query
    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Example
