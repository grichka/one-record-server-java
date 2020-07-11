
package org.iata.cargo.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import cz.cvut.kbss.jopa.model.annotations.OWLClass;
import cz.cvut.kbss.jopa.model.annotations.OWLDataProperty;
import cz.cvut.kbss.jopa.model.annotations.ParticipationConstraint;
import cz.cvut.kbss.jopa.model.annotations.ParticipationConstraints;
import cz.cvut.kbss.jopa.model.annotations.Types;
import io.swagger.annotations.ApiModelProperty;
import org.iata.cargo.Vocabulary;

import java.io.Serializable;
import java.util.Set;


/**
 * Customs information details
 * 
 * This class was generated by OWL2Java 0.14.6
 * 
 */
@OWLClass(iri = Vocabulary.s_c_CustomsInfo)
public class CustomsInfo
    extends LogisticsObject
    implements Serializable
{

    @Types
    @JsonProperty("@type")
    @ApiModelProperty(allowableValues = Vocabulary.s_c_CustomsInfo)
    protected Set<String> types;

    /**
     * Customs content code. Refer CXML Code List 1.100, e.g. IST - Security Textual StatementNumber, M - Movement Reference Number
     * 
     */
    @OWLDataProperty(iri = Vocabulary.s_p_customsInfoContentCode)
    @ParticipationConstraints({
        @ParticipationConstraint(owlObjectIRI = "http://www.w3.org/2001/XMLSchema#string", max = 1)
    })
    @JsonProperty(Vocabulary.s_p_customsInfoContentCode)
    protected String customsInfoContentCode;
    /**
     * Customs country code.
     * 
     */
    @OWLDataProperty(iri = Vocabulary.s_p_customsInfoCountryCode)
    @ParticipationConstraints({
        @ParticipationConstraint(owlObjectIRI = "http://www.w3.org/2001/XMLSchema#string", max = 1)
    })
    @JsonProperty(Vocabulary.s_p_customsInfoCountryCode)
    protected String customsInfoCountryCode;
    /**
     * Free text for customs remarks
     * 
     */
    @OWLDataProperty(iri = Vocabulary.s_p_customsInfoNote)
    @ParticipationConstraints({
        @ParticipationConstraint(owlObjectIRI = "http://www.w3.org/2001/XMLSchema#string", max = 1)
    })
    @JsonProperty(Vocabulary.s_p_customsInfoNote)
    protected String customsInfoNote;
    /**
     * Customs subject code. Refer CXML Code List 1.19, e.g. IMP for import, EXP for export, AGT for Agent, ISS for The Regulated Agent Issuing the Security Status for rdf:type Consignment etc.   At least one of the three elements (Country Code, Information Identifier or Customs, Security and Regulatory Control Information Identifier) must be completed
     * 
     */
    @OWLDataProperty(iri = Vocabulary.s_p_customsInfoSubjectCode)
    @ParticipationConstraints({
        @ParticipationConstraint(owlObjectIRI = "http://www.w3.org/2001/XMLSchema#string", max = 1)
    })
    @JsonProperty(Vocabulary.s_p_customsInfoSubjectCode)
    protected String customsInfoSubjectCode;
    /**
     * Information for customs submission
     * 
     */
    @OWLDataProperty(iri = Vocabulary.s_p_customsInformation)
    @ParticipationConstraints({
        @ParticipationConstraint(owlObjectIRI = "http://www.w3.org/2001/XMLSchema#string", max = 1)
    })
    @JsonProperty(Vocabulary.s_p_customsInformation)
    protected String customsInformation;

    public void setCustomsInfoContentCode(String customsInfoContentCode) {
        this.customsInfoContentCode = customsInfoContentCode;
    }

    public String getCustomsInfoContentCode() {
        return customsInfoContentCode;
    }

    public void setCustomsInfoCountryCode(String customsInfoCountryCode) {
        this.customsInfoCountryCode = customsInfoCountryCode;
    }

    public String getCustomsInfoCountryCode() {
        return customsInfoCountryCode;
    }

    public void setCustomsInfoNote(String customsInfoNote) {
        this.customsInfoNote = customsInfoNote;
    }

    public String getCustomsInfoNote() {
        return customsInfoNote;
    }

    public void setCustomsInfoSubjectCode(String customsInfoSubjectCode) {
        this.customsInfoSubjectCode = customsInfoSubjectCode;
    }

    public String getCustomsInfoSubjectCode() {
        return customsInfoSubjectCode;
    }

    public void setCustomsInformation(String customsInformation) {
        this.customsInformation = customsInformation;
    }

    public String getCustomsInformation() {
        return customsInformation;
    }


    public Set<String> getTypes() {
        return types;
    }


    public void setTypes(Set<String> types) {
        this.types = types;
    }

}
