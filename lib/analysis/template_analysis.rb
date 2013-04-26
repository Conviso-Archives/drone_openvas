require File.join(File.dirname(__FILE__), 'interface')
require 'digest/md5'

module Analysis
  class Template < Analysis::Interface

    def analyse(issue = nil)
      @config.keys.each do |k|
        if Digest::MD5.hexdigest(issue[:name]) =~ /#{k}/i
          issue[:template_id] = @config[k]
        end
      end
      return issue
    end

  end
end