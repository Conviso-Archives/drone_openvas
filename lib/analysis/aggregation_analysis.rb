require File.join(File.dirname(__FILE__), 'interface')
require 'digest/sha1'

module Analysis
  class Aggregation < Analysis::Interface::Bulk
    def analyse(issues = [])
      new_issues = {}
      issues.each do |i|
        if new_issues[i[:name]].nil?
          new_issues[i[:name]] = i
          new_issues[i[:name]][:affected_component] = [new_issues[i[:name]][:affected_component]]
        else
          @debug.info('Aggregating issue ...')
          new_issues[i[:name]][:url] = new_issues[i[:name]][:url].to_s + "\n#{i[:url].to_s}"
          new_issues[i[:name]][:affected_component] = [] if new_issues[i[:name]][:affected_component].nil?
          new_issues[i[:name]][:affected_component]  << i[:affected_component]

          new_issues[i[:name]][:_hash] = Digest::SHA1.hexdigest(new_issues[i[:name]][:_hash].to_s + i[:_hash].to_s)
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
