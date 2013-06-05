require File.join(File.dirname(__FILE__), 'interface')

module Analysis
  class Replace < Analysis::Interface::Individual

    def analyse(issue = nil)
      @config.select{|k,v| v == 'none'}.each {|k,v| @config[k] = ''}
      issue.keys.each do |k|
        @config.each {|k2,v| issue[k].to_s.gsub!(/#{k2.to_s}/i, v)} 
      end
      return issue
    end
    
  end
end