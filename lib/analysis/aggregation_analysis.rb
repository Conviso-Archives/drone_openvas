require File.join(File.dirname(__FILE__), 'interface')
require 'digest/sha1'

module Analysis
  class Aggregation < Analysis::Interface
    def bulk_analyse(issues = [])
      new_issues = {}
      issues.each do |i|
        if new_issues[i[:name]].nil?
          new_issues[i[:name]] = i
          new_issues[i[:name]][:affected_component] = [new_issues[i[:name]][:affected_component]]
        else  
          @debug.info('Aggregating issue ...')
  #        new_issues[i[:name]][:url] += "\n#{i[:url]}"
          new_issues[i[:name]][:affected_component] = [] if new_issues[i[:name]][:affected_component].nil?
          new_issues[i[:name]][:affected_component]  << i[:affected_component]
          strhash = ""
          strhash << new_issues[i[:name]][:hash].to_s
          strhash << i[:hash].to_s
          new_issues[i[:name]][:hash] = Digest::SHA1.hexdigest(strhash)
        end
      end
      
      return_issues = new_issues.values
      return_issues.each do |i| 
        i[:affected_component] = i[:affected_component].join("\n\n")
      end
      return return_issues
    end
  end
end
