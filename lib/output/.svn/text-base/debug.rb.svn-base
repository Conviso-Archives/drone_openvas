module Output
  class Debug
    @@level = 0
     
    class << self
      attr_accessor 'level'
     end
    
    attr_accessor :level
    def initialize(output_file = '')
      @output = File.exists?(output_file) ? File.open(output_file) : STDOUT
    end
    
    def error(msg)
      @output.puts "[E #{__get_time}] #{msg}"
    end
    
    def warning(msg)
      @output.puts "[W #{__get_time}] #{msg}"
    end
    
    def info(msg)
      @output.puts "[I #{__get_time}] #{msg}"
    end
    
    private
    def __get_time
      now = DateTime.now
      "#{now.year}-#{now.month}-#{now.day} #{now.hour}:#{now.min}"
    end
  end
end