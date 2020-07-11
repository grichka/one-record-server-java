
package org.iata.cargo.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import cz.cvut.kbss.jopa.model.annotations.OWLClass;
import cz.cvut.kbss.jopa.model.annotations.OWLDataProperty;
import cz.cvut.kbss.jopa.model.annotations.OWLObjectProperty;
import cz.cvut.kbss.jopa.model.annotations.ParticipationConstraint;
import cz.cvut.kbss.jopa.model.annotations.ParticipationConstraints;
import cz.cvut.kbss.jopa.model.annotations.Types;
import io.swagger.annotations.ApiModelProperty;
import org.iata.cargo.Vocabulary;

import java.io.Serializable;
import java.util.Set;


/**
 * Shipment details
 * 
 * This class was generated by OWL2Java 0.14.6
 * 
 */
@OWLClass(iri = Vocabulary.s_c_Shipment)
public class Shipment
    extends LogisticsObject
    implements Serializable
{

    @Types
    @JsonProperty("@type")
    @ApiModelProperty(allowableValues = Vocabulary.s_c_Shipment)
    protected Set<String> types;

    /**
     * Details of contained piece(s)
     * 
     */
    @OWLObjectProperty(iri = Vocabulary.s_p_containedPiece_A)
    @JsonProperty(Vocabulary.s_p_containedPiece_A)
    protected Set<Piece> containedPiece;
    /**
     * Dimensions details
     * 
     */
    @OWLObjectProperty(iri = Vocabulary.s_p_dimensions_A_A)
    @JsonProperty(Vocabulary.s_p_dimensions_A_A)
    protected Set<Dimensions> dimensions;
    /**
     * Reference document details
     * 
     */
    @OWLObjectProperty(iri = Vocabulary.s_p_externalReference_A)
    @JsonProperty(Vocabulary.s_p_externalReference_A)
    protected Set<ExternalReference> externalReference;
    /**
     * Insurance details
     * 
     */
    @OWLObjectProperty(iri = Vocabulary.s_p_insurance)
    @JsonProperty(Vocabulary.s_p_insurance)
    protected Set<Insurance> insurance;
    /**
     * Weight details
     * 
     */
    @OWLObjectProperty(iri = Vocabulary.s_p_totalGrossWeight)
    @ParticipationConstraints({
        @ParticipationConstraint(owlObjectIRI = Vocabulary.s_c_Thing, min = 1, max = -1),
        @ParticipationConstraint(owlObjectIRI = Vocabulary.s_c_Thing, max = 1)
    })
    @JsonProperty(Vocabulary.s_p_totalGrossWeight)
    protected Value totalGrossWeight;
    /**
     * Volumetric weight details
     * 
     */
    @OWLObjectProperty(iri = Vocabulary.s_p_volumetricWeight_A)
    @ParticipationConstraints({
        @ParticipationConstraint(owlObjectIRI = Vocabulary.s_c_Thing, min = 1, max = -1)
    })
    @JsonProperty(Vocabulary.s_p_volumetricWeight_A)
    protected Set<VolumetricWeight> volumetricWeight;
    /**
     * Waybill unique identifier (AWB or HWB)
     * 
     */
    @OWLObjectProperty(iri = Vocabulary.s_p_waybillNumber_A_A)
    @ParticipationConstraints({
        @ParticipationConstraint(owlObjectIRI = Vocabulary.s_c_Thing, min = 1, max = -1),
        @ParticipationConstraint(owlObjectIRI = Vocabulary.s_c_Thing, max = 1)
    })
    @JsonProperty(Vocabulary.s_p_waybillNumber_A_A)
    protected Waybill waybillNumber;
    /**
     * General goods description
     * 
     */
    @OWLDataProperty(iri = Vocabulary.s_p_goodsDescription_A)
    @ParticipationConstraints({
        @ParticipationConstraint(owlObjectIRI = "http://www.w3.org/2001/XMLSchema#string", max = 1)
    })
    @JsonProperty(Vocabulary.s_p_goodsDescription_A)
    protected String goodsDescription;
    /**
     * Total Piece Count
     * 
     */
    @OWLDataProperty(iri = Vocabulary.s_p_totalPieceCount)
    @ParticipationConstraints({
        @ParticipationConstraint(owlObjectIRI = "http://www.w3.org/2001/XMLSchema#integer", max = 1)
    })
    @JsonProperty(Vocabulary.s_p_totalPieceCount)
    protected Integer totalPieceCount;
    /**
     * Total SLAC of all piece groups 
     * 
     */
    @OWLDataProperty(iri = Vocabulary.s_p_totalSLAC)
    @ParticipationConstraints({
        @ParticipationConstraint(owlObjectIRI = "http://www.w3.org/2001/XMLSchema#integer", max = 1)
    })
    @JsonProperty(Vocabulary.s_p_totalSLAC)
    protected Integer totalSLAC;

    public void setContainedPiece(Set<Piece> containedPiece) {
        this.containedPiece = containedPiece;
    }

    public Set<Piece> getContainedPiece() {
        return containedPiece;
    }

    public void setDimensions(Set<Dimensions> dimensions) {
        this.dimensions = dimensions;
    }

    public Set<Dimensions> getDimensions() {
        return dimensions;
    }

    public void setExternalReference(Set<ExternalReference> externalReference) {
        this.externalReference = externalReference;
    }

    public Set<ExternalReference> getExternalReference() {
        return externalReference;
    }

    public void setInsurance(Set<Insurance> insurance) {
        this.insurance = insurance;
    }

    public Set<Insurance> getInsurance() {
        return insurance;
    }

    public void setTotalGrossWeight(Value totalGrossWeight) {
        this.totalGrossWeight = totalGrossWeight;
    }

    public Value getTotalGrossWeight() {
        return totalGrossWeight;
    }

    public void setVolumetricWeight(Set<VolumetricWeight> volumetricWeight) {
        this.volumetricWeight = volumetricWeight;
    }

    public Set<VolumetricWeight> getVolumetricWeight() {
        return volumetricWeight;
    }

    public void setWaybillNumber(Waybill waybillNumber) {
        this.waybillNumber = waybillNumber;
    }

    public Waybill getWaybillNumber() {
        return waybillNumber;
    }

    public void setGoodsDescription(String goodsDescription) {
        this.goodsDescription = goodsDescription;
    }

    public String getGoodsDescription() {
        return goodsDescription;
    }

    public void setTotalPieceCount(Integer totalPieceCount) {
        this.totalPieceCount = totalPieceCount;
    }

    public Integer getTotalPieceCount() {
        return totalPieceCount;
    }

    public void setTotalSLAC(Integer totalSLAC) {
        this.totalSLAC = totalSLAC;
    }

    public Integer getTotalSLAC() {
        return totalSLAC;
    }


    public Set<String> getTypes() {
        return types;
    }


    public void setTypes(Set<String> types) {
        this.types = types;
    }


}
