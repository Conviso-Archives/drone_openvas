module Analysis
  module Interface
    class Bulk
      attr_accessor :config, :debug
      def initialize (config = nil, debug = nil)
        @config = config
        @debug = debug
      end

      def _analyse(issues = [])
        begin
          raise AnalyseException, "[#{self.class}] Parameter should be an Array but is a [#{issues.class}]" unless (issues.instance_of?(Array))
          return analyse(issues)
        rescue => e
          raise AnalyseException, "[#{self.class}] Error during a bulk analysis"
        end
      end
      
      def analyse(issues = [])
        raise raise AnalyseException, "analyse() method should be implemented"
      end
    end
    
    class Individual
      attr_accessor :config, :debug
      def initialize (config = nil, debug = nil)
        @config = config
        @debug = debug
      end

      def _analyse(issue = nil)
        begin
          raise AnalyseException, "[#{self.class}] Parameter should be a Hash" unless (issue.instance_of?(Hash))
          return analyse(issue)
        rescue => e
          raise AnalyseException, "[#{self.class}] Error during an individual analysis"
        end
      end

      def analyse(issue = nil)
        raise raise AnalyseException, "analyse() method should be implemented"
      end
    end
    
  end
  
  class AnalyseException < Exception
  end
end