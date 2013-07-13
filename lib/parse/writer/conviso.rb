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
require 'base64'
require 'builder'

module Parse
  module Writer
    class Conviso
      def self.build_xml(issue, config)
        xml = Builder::XmlMarkup.new(:ident => 2)
        xml.instruct! :xml, :encoding => 'UTF-8'

        xml.scan do |s|
          s.header do |h|
            h.tool "OpenVAS"
            h.scope config['client']
            h.project config['project_id'].to_s
            h.duration issue[:duration].to_s
            h.timestamp Time.now
          end

          
          s.vulnerabilities do |vs|
            vs.vulnerability('id' => issue['_hash'] ) do |v|
              v.hash issue['_hash']
              issue[:name] << " - Host: "+ issue[:host].to_s
              v.title Base64.encode64(issue[:name].to_s)
              tmp2=""
              tmp2=issue[:description].to_s
              tmp2.gsub( /Solution :/, "\nSolution :")

              test=tmp2.split("\n")
              solution=""
              references=""
              description=""
              counter=0
               
              test.each { |tmp|
                           if tmp.match('Solution:')
  		            counter=1
 		           end
 
          		   if tmp.match('References:')
  		            counter=2
 		           end

 		           if counter == 0
  		            description << tmp + "\n"
		           end

 		           if counter == 1 
                            solution << tmp + "\n"
                            
 		           end

 		           if counter == 2
                            references << tmp + "\n"
                            
                           end
              }
              
              solution=solution.gsub( /Solution:|Solution :/, " ")
              references=references.gsub( /References:|References :/, " ")
              description=description.gsub( /Overview:|Overview :/, " ")

              if description.empty? 
               description="Information N/A"
              end

              if references.empty? 
               references="Information N/A"
              end

              if solution.empty? 
               solution="Information N/A"
              end


              v.description Base64.encode64(description.to_s)
       
              v.optional do |vo|
                vo.impact issue[:risk_factor].to_s.downcase                
                vo.affected_component Base64.encode64(issue[:name].to_s  )
                vo.control Base64.encode64(solution.to_s)
                vo.reference Base64.encode64(references.to_s)
                vo.reproduction Base64.encode64(issue[:cve].to_s)
                vo.exploitability issue[:risk_factor].to_s.downcase
                vo.template_id issue[:template_id].to_s.downcase
              end # optional
            end # vulnerability
          end # vulnerabilities
        end # scan

      end

    end
  end
end
