require 'rexml/document'

module Parse
  module DOM
    class Openvas
      def parse_file(xml_file)
        struct = nil
        begin
	        fd=File.new(xml_file)
	        doc = REXML::Document.new fd
	        $rows=doc.root
	        struct = __extract_xml()
	      rescue Exception => e
	        raise e
        end
        return struct
      end
     
     
      private
      # TODO: Refatorar esse metodo
      def __extract_xml()
        begin
          output = {}
          output[:results] = []
          output[:duration]=[]
          output[:start_datetime]=[]
          output[:toolname]=[]

          duration=$rows.elements['//report/scan_end'].text.to_s
          toolname="openvas"
          start=$rows.elements['//report/scan_start'].text.to_s

          path="//report/results/result"
          output[:results] = $rows.elements.collect(path) do |row|  
            {
              :hash => row.attributes['id'],
# o que tiver dentro da tag nvt/*
              :name => row.elements['nvt/name'].text.to_s,
#o que tiver dentro da tag result
              :host => row.elements['host'].text.to_s,
              :port => row.elements['port'].text.to_s,
              :description => row.elements['description'].text.to_s,
              :original_threat => row.elements['original_threat'].text.to_s,
              :family => row.elements['nvt/family'].text.to_s,
              :cve => row.elements['nvt/cve'].text.to_s,
              :risk_factor => row.elements['nvt/risk_factor'].text.to_s
            }
          end

          output[:scan_end]=duration
          output[:scan_start]=start
          output[:toolname]=toolname


          # eliminando repetidos
          output[:results].uniq!
       
        rescue Exception => e
          raise Exception.new 'XML with invalid format'
        end 
        return output
      end
      
    end
  end
end
