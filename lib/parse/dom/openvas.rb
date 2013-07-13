#
# Copyright 2013 by Antonio Costa (acosta@conviso.com.br)
#
# This file is part of the Drone openvas project.
# Drone Template is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
          output[:issues] = []
          output[:duration]=[]
          output[:start_datetime]=[]
          output[:toolname]=[]

          duration=$rows.elements['//report/scan_end'].text.to_s
          toolname="openvas"
          start=$rows.elements['//report/scan_start'].text.to_s

          path="//report/results/result"
          output[:issues] = $rows.elements.collect(path) do |row|  
            {
              :_hash => row.attributes['id'],
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
          output[:issues].uniq!
       
        rescue Exception => e
          raise Exception.new 'XML with invalid format'
        end 
        return output
      end
      
    end
  end
end
