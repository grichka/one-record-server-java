
package org.iata.cargo.model;

import java.io.Serializable;
import java.util.Date;
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
 * Carrier signature details
 * 
 * This class was generated by OWL2Java 0.14.1
 * 
 */
@OWLClass(iri = Vocabulary.s_c_CarrierSignature)
public class CarrierSignature
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
     * at (place)
     * 
     */
    @OWLObjectProperty(iri = Vocabulary.s_p_location_A)
    protected Set<Location> location;
    /**
     * Signature of Issuing Carrier of its agent
     * 
     */
    @OWLObjectProperty(iri = Vocabulary.s_p_signatoryCompany)
    protected Set<Company> signatoryCompany;
    /**
     * Executed on (date)
     * 
     */
    @OWLDataProperty(iri = Vocabulary.s_p_date_A_A)
    protected Set<Date> date;

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
        return ((((("CarrierSignature {"+ name)+"<")+ id)+">")+"}");
    }

    public void setLocation(Set<Location> location) {
        this.location = location;
    }

    public Set<Location> getLocation() {
        return location;
    }

    public void setSignatoryCompany(Set<Company> signatoryCompany) {
        this.signatoryCompany = signatoryCompany;
    }

    public Set<Company> getSignatoryCompany() {
        return signatoryCompany;
    }

    public void setDate(Set<Date> date) {
        this.date = date;
    }

    public Set<Date> getDate() {
        return date;
    }

}
