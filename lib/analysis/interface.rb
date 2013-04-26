module Analysis
  class Interface
    attr_accessor :config, :debug
    
    def initialize (config = nil, debug = nil)
      @config = config
      @debug = debug
    end

    def bulk_analyse(issues = [])
      return issues
    end

    def analyse(issue = nil)
      return issue
    end
  end
end