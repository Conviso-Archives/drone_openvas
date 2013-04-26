require 'libxml'

include LibXML

# Parse::SAX::Openvas

module Parse
  module SAX
    class Openvas
      def parse_file(xml_file)
        parser = XML::SaxParser.file(xml_file)
        parser.callbacks = OpenvasSAXCallback.new()
        parser.parse
        return parser.callbacks.struct
      end
    end
    class OpenvasSAXCallback
      include XML::SaxParser::Callbacks
      
      attr_reader :struct
      def on_start_document
        @result = {}
        @header = {}
        @results = []
        @current = ''
      end

      def on_end_document
        @results.uniq!
        @results.each do |i|
          i[:affected_component] = "#{ i[:name] } \n"
        end
        @struct = {}
        @struct[:results] = @results
        @struct[:duration] = @header[:scan_end]
        @struct[:start_datetime] = @header[:scan_start]
        @struct[:toolname] = "OpenVAS"
      end
# elemento inicial , <result> onde se encontra as vulns
      def on_start_element_ns(element, attributes, prefix, uri, namespaces)
        if element == 'result'
          @in_result = true
          @result = {}
          @result['hash'] = attributes['id']
        end

        if element == 'reference'
          @result[:reference] = @result[:name].to_s + "#{attributes['cwe']} - #{attributes['family']}\n"
        end
        
        if element =~ /^(host|port|name|description|original_threat|family|cwe|scan_start|risk_factor|scan_end)$/i
          @in_sub_element = true
          @current = element
        end
         
          

        if element == 'variations'
          @result[:variations] = []
        end
        
        if element  == 'variation'
          @in_variation = true
          @variation = []
        end
        
        if @in_variation && element =~ /^(host|port)$/
          @in_sub_variation = true
          @current = element
        end
        
        if element =~ /^(scan_start|name|scan_end)$/i
          @in_header_element = true
          @current = element
        end
      end

      def on_characters(chars)
        if @in_result && @in_sub_element
          @result[@current.to_sym] = chars.to_s
        end
        
        if @in_result && @in_sub_variation
          @variation << chars.to_s
        end
        
        if @in_header_element
          @header[@current.to_sym] = chars.to_s
        end
      end
      
      def on_end_element(element)
        if element == 'result'
          @in_result = false
          @results << @result unless @result.empty?
        end

        if element  == 'variation'
          @in_variation = false
          @result[:variations] << @variation
        end
        
        if @in_variation && element =~ /^(host|port)$/
          @in_sub_variation = false
        end

        if element =~ /^(host|port|name|description|original_threat|family|cwe|scan_start|scan_end|risk_factor)$/i
          @in_sub_element = false
        end
        
        if element =~ /^(scan_start|scan_end)$/i
          @in_header_element = false
        end
      end

    end
  end
end

