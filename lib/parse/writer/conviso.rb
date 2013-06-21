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
            h.project config['project_id']
            h.duration issue[:duration].to_s
            h.timestamp Time.now
          end

          
          s.vulnerabilities do |vs|
            vs.vulnerability('id' => issue['_hash'] ) do |v|
              v.hash issue['_hash']
              issue[:name] << " - Host: "+ issue[:host].to_s
              v.title Base64.encode64(issue[:name].to_s)
              issue[:description] << "Host: "+ issue[:host].to_s + "\n"
              tmp=""
              tmp=issue[:description].to_s
              test=tmp.split("\n")
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

