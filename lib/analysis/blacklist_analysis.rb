require File.join(File.dirname(__FILE__), 'interface')
require 'digest/md5'

module Analysis
  class Blacklist < Analysis::Interface
    def analyse(issue = nil)
      if Digest::MD5.hexdigest(issue[:name]) =~ /(#{@config.join('|')})/i
        @debug.info("The issue #{issue[:_hash]} was blacklisted")
        return {}
      else
        return issue
      end
    end
  end
end
