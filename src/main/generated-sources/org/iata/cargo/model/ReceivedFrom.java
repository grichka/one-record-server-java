
package org.iata.cargo.model;

import java.io.Serializable;
import java.util.Map;
import java.util.Set;
import cz.cvut.kbss.jopa.model.annotations.Id;
import cz.cvut.kbss.jopa.model.annotations.OWLAnnotationProperty;
import cz.cvut.kbss.jopa.model.annotations.OWLClass;
import cz.cvut.kbss.jopa.model.annotations.OWLDataProperty;
import cz.cvut.kbss.jopa.model.annotations.OWLObjectProperty;
import cz.cvut.kbss.jopa.model.annotations.Properties;
import cz.cvut.kbss.jopa.model.annotations.Types;
import cz.cvut.kbss.jopa.vocabulary.RDFS;
import org.iata.cargo.Vocabulary;


/**
 * Known Consignor or Regulated Agent reference
 * 
 * This class was generated by OWL2Java 0.14.1
 * 
 */
@OWLClass(iri = Vocabulary.s_c_ReceivedFrom)
public class ReceivedFrom
    implements Serializable
{

    @Id(generated = true)
    protected String id;
    @OWLAnnotationProperty(iri = RDFS.LABEL)
    protected String name;
    @OWLAnnotationProperty(iri = cz.cvut.kbss.jopa.vocabulary.DC.Elements.DESCRIPTION)
    protected String description;
    @Types
    protected Set<String> types;
    @Properties
    protected Map<String, Set<String>> properties;
    /**
     * Regulated entity identifier (e.g. Regulated Agent Identifier) is mandatory
     * 
     */
    @OWLObjectProperty(iri = Vocabulary.s_p_regulatedEntityIdentifier)
    protected Set<Company> regulatedEntityIdentifier;
    /**
     * Expiry date 4 digits month/year
     * 
     */
    @OWLDataProperty(iri = Vocabulary.s_p_expiryDate)
    protected Set<String> expiryDate;
    /**
     * Party type - e.g. RA - Regulated Agent, KC - Known Consignor, AO - Aircraft Operator, RC - Regulated Carrier
     * 
     */
    @OWLDataProperty(iri = Vocabulary.s_p_regulatedPartyType)
    protected Set<String> regulatedPartyType;

    public void setId(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public void setTypes(Set<String> types) {
        this.types = types;
    }

    public Set<String> getTypes() {
        return types;
    }

    public void setProperties(Map<String, Set<String>> properties) {
        this.properties = properties;
    }

    public Map<String, Set<String>> getProperties() {
        return properties;
    }

    @Override
    public String toString() {
        return ((((("ReceivedFrom {"+ name)+"<")+ id)+">")+"}");
    }

    public void setRegulatedEntityIdentifier(Set<Company> regulatedEntityIdentifier) {
        this.regulatedEntityIdentifier = regulatedEntityIdentifier;
    }

    public Set<Company> getRegulatedEntityIdentifier() {
        return regulatedEntityIdentifier;
    }

    public void setExpiryDate(Set<String> expiryDate) {
        this.expiryDate = expiryDate;
    }

    public Set<String> getExpiryDate() {
        return expiryDate;
    }

    public void setRegulatedPartyType(Set<String> regulatedPartyType) {
        this.regulatedPartyType = regulatedPartyType;
    }

    public Set<String> getRegulatedPartyType() {
        return regulatedPartyType;
    }

}
